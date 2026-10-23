"""Safe YAML loading that rejects duplicate source keys before merge expansion."""
import yaml

class StrictSafeLoader(yaml.SafeLoader):
    def flatten_mapping(self, node):
        # PyYAML flattens inline merge mappings without constructing them. Check
        # each original mapping here, before flattening can erase duplicate keys.
        checked = self.__dict__.setdefault('_source_checked', set())
        if id(node) in checked:
            return
        checked.add(id(node))
        seen = set()
        for key_node, _ in node.value:
            key = '<<' if key_node.tag == 'tag:yaml.org,2002:merge' else self.construct_object(key_node, deep=False)
            try:
                if key in seen:
                    raise yaml.constructor.ConstructorError('while reading a mapping', node.start_mark,
                        f'duplicate YAML key: {key!r}', key_node.start_mark)
                seen.add(key)
            except TypeError:
                raise yaml.constructor.ConstructorError('while reading a mapping', node.start_mark,
                    'mapping key must be hashable', key_node.start_mark)
        return super().flatten_mapping(node)

def load(data):
    return yaml.load(data, Loader=StrictSafeLoader)
