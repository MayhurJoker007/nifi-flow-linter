"""Reads NiFi flow files into a simple walkable structure.

Two formats are supported:
  * a flow definition downloaded from the UI or the registry (top level "flowContents")
  * the instance's own conf/flow.json.gz (top level "rootGroup")
"""
import gzip
import json
from dataclasses import dataclass, field


@dataclass
class Component:
    id: str
    name: str
    kind: str                 # PROCESSOR, CONNECTION, FUNNEL, INPUT_PORT, OUTPUT_PORT, ...
    group_path: str           # "Root / Orders / ERP" for messages
    raw: dict

    @property
    def type(self):
        return self.raw.get('type', '')

    @property
    def short_type(self):
        return self.type.rsplit('.', 1)[-1]

    @property
    def where(self):
        return '%s > %s' % (self.group_path, self.name or self.short_type or self.id)


@dataclass
class Group:
    id: str
    name: str
    path: str
    depth: int
    raw: dict
    processors: list = field(default_factory=list)
    connections: list = field(default_factory=list)
    funnels: list = field(default_factory=list)
    input_ports: list = field(default_factory=list)
    output_ports: list = field(default_factory=list)
    children: list = field(default_factory=list)


@dataclass
class Flow:
    root: Group
    parameter_contexts: dict

    def groups(self):
        stack = [self.root]
        while stack:
            g = stack.pop()
            yield g
            stack.extend(reversed(g.children))

    def processors(self):
        for g in self.groups():
            yield from g.processors

    def connections(self):
        for g in self.groups():
            yield from g.connections

    def component(self, component_id):
        for g in self.groups():
            for c in g.processors + g.funnels + g.input_ports + g.output_ports:
                if c.id == component_id:
                    return c
        return None


def load(path):
    opener = gzip.open if str(path).endswith('.gz') else open
    with opener(path, 'rt', encoding='utf-8') as f:
        data = json.load(f)
    return parse(data)


def parse(data):
    if 'flowContents' in data:
        root = data['flowContents']
        contexts = data.get('parameterContexts', {})
    elif 'rootGroup' in data:
        root = data['rootGroup']
        contexts = {c['name']: c for c in data.get('parameterContexts', [])}
    else:
        raise ValueError('not a NiFi flow: expected "flowContents" or "rootGroup" at the top level')
    return Flow(_group(root, 'Root' if not root.get('name') else root['name'], 0), contexts)


def _group(raw, path, depth):
    g = Group(id=raw.get('identifier', raw.get('instanceIdentifier', '')), name=raw.get('name', ''), path=path,
              depth=depth, raw=raw)

    def comp(item, kind):
        return Component(item.get('identifier', ''), item.get('name', ''), kind, path, item)

    g.processors = [comp(p, 'PROCESSOR') for p in raw.get('processors', [])]
    g.connections = [comp(c, 'CONNECTION') for c in raw.get('connections', [])]
    g.funnels = [comp(f, 'FUNNEL') for f in raw.get('funnels', [])]
    g.input_ports = [comp(p, 'INPUT_PORT') for p in raw.get('inputPorts', [])]
    g.output_ports = [comp(p, 'OUTPUT_PORT') for p in raw.get('outputPorts', [])]
    g.children = [_group(child, '%s / %s' % (path, child.get('name', '?')), depth + 1)
                  for child in raw.get('processGroups', [])]
    return g
