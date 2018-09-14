# pylint: disable=E1101,R0903
"""TwoWayTable - A better bijective Map"""


class TwoWayTable():
    """A TwoWayTable is a way to keep two dictionaries synchronized with each
    other. It aims to be a bijective mapping, without the problem of
    key-space/value-space overlap. Meaning a key of one k/v pair can still be
    the value of another k/v pair.

    Example:
        # Members 'father'/'son' (dicts) and 'fathers'/'sons' (lists) are
        # generated automatically
        >>> twt = TwoWayTable("father", "son")

        # Read as the father of Prince William is Prince Charles
        >>> twt.father["Prince William"] = "Prince Charles"
        # In the background: twt.son["Prince Charles"] = "Prince William"

        # Read as the father of Prince Louis is the son of Prince Charles
        >>> twt.father["Prince Louis"] = twt.son["Prince Charles"]

        # Note: This can be a bit tricky.
        >>> print(twt.fathers)
        [ "Prince Charles", "Prince William" ]
        >>> print(twt.sons)
        [ "Prince William", "Prince Louis" ]
    """

    def __init__(self, key_name, value_name, *,
                 keylist_name=None, valuelist_name=None):
        """Creates synchronized dictionaries as member variables of this
        object under the given names. If no list names are supplied the keys
        of the dictionaries are available under their names + 's' (see example
        in the module docstring) as member variables as well."""
        if keylist_name is None:
            keylist_name = key_name + "s"

        if valuelist_name is None:
            valuelist_name = value_name + "s"

        self.dict1 = {}
        self.dict2 = {}
        setattr(self, key_name, PairedDict(self.dict1, self.dict2))
        setattr(self, value_name, PairedDict(self.dict2, self.dict1))
        setattr(self, keylist_name, self.values)
        setattr(self, valuelist_name, self.keys)

    @property
    def keys(self):
        """Returns the keys of the first dictionary/the values of the second
        dictionary"""
        return self.dict1.keys()

    @property
    def values(self):
        """Returns the values of the first dictionary/the keys of the second
        dictionary"""
        return self.dict1.values()


class PairedDict():
    """Saves the keys and values of the wrapped dict as values and keys in the
    partnered dict. But not the other way around! See TwoWayTable for that."""
    def __init__(self, wrapped_dict, partner_dict):
        self.internal = wrapped_dict
        self.partner = partner_dict

    def __setitem__(self, key, item):
        self.internal[key] = item

        # check to avoid infinite recursion
        if item not in self.partner:
            self.partner[item] = key

    def __getitem__(self, key):
        return self.internal[key]

    def __delitem__(self, key):
        item = self.internal[key]

        del self.internal[key]

        # check to avoid infinite recursion
        if item in self.partner:
            del self.partner[item]

    def __len__(self):
        return len(self.internal)

    def __iter__(self):
        return iter(self.internal)

    def clear(self):
        """Clears both dictionaries."""
        self.internal.clear()

        # check to avoid infinite recursion
        if len(self.partner):
            self.partner.clear()
