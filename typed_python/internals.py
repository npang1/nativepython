#   Copyright 2018 Braxton Mckee
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

from types import FunctionType

import typed_python._types
import nativepython.python.inspect_override as inspect

from typed_python.hash import sha_hash
from typed_python._types import TupleOf, Tuple, NamedTuple, OneOf, ConstDict, \
                                Alternative, Value, serialize, deserialize, Int8, \
                                Int16, Int32, UInt8, UInt32, UInt64, NoneType, Function

class Member:
    def __init__(self, t):
        self.t = t

class ClassMetaNamespace:
    def __init__(self):
        self.ns = {}
        self.order = []

    def __getitem__(self, k):
        return self.ns[k]

    def __setitem__(self, k, v):
        self.ns[k] = v
        self.order.append((k,v))

def makeFunction(name, f):
    spec = inspect.getfullargspec(f)

    def getAnn(argname):
        if argname not in spec.annotations:
            return None
        else:
            ann = spec.annotations.get(argname)
            if ann is None:
                return type(None)
            else:
                return ann

    arg_types = []
    for i, argname in enumerate(spec.args):
        if spec.defaults is not None:
            if i >= len(spec.args) - len(spec.defaults):
                default = (spec.defaults[i-(len(spec.args) - len(spec.defaults))],)
            else:
                default = None
        else:
            default = None

        arg_types.append((argname, getAnn(argname), default, False, False))

    return_type = None

    if 'return' in spec.annotations:
        ann = spec.annotations.get('return')
        if ann is None:
            ann = type(None)
        return_type = ann

    if spec.varargs is not None:
        arg_types.append((spec.varargs, getAnn(spec.varargs), None, True, False))

    for arg in spec.kwonlyargs:
        arg_types.append((arg, getAnn(arg), (spec.kwonlydefaults.get(arg),), False, False))

    if spec.varkw is not None:
        arg_types.append((spec.varkw, getAnn(spec.varkw), None, False, True))

    return Function(name, return_type, f, tuple(arg_types))

class ClassMetaclass(type):
    @classmethod
    def __prepare__(cls, *args, **kwargs):
        return ClassMetaNamespace()

    def __new__(cls, name, bases, namespace, **kwds):
        if not bases:
            return type.__new__(cls, name,bases, namespace.ns, **kwds)

        members = []
        memberFunctions = {}
        staticFunctions = {}
        classMembers = []

        for eltName, elt in namespace.order:
            if isinstance(elt, Member):
                members.append((eltName, elt.t))
            elif isinstance(elt, staticmethod):
                if eltName not in staticFunctions:
                    staticFunctions[eltName] = makeFunction(eltName, elt.__func__)
                else:
                    staticFunctions[eltName] = Function(staticFunctions[eltName], makeFunction(eltName, elt.__func__))
            elif isinstance(elt, FunctionType):
                if eltName not in memberFunctions:
                    memberFunctions[eltName] = makeFunction(eltName, elt)
                else:
                    memberFunctions[eltName] = Function(memberFunctions[eltName], makeFunction(eltName, elt))
            else:
                classMembers.append((eltName, elt))

        return typed_python._types.Class(
            name, 
            tuple(members), 
            tuple(memberFunctions.items()), 
            tuple(staticFunctions.items()), 
            tuple(classMembers)
            )

class Class(metaclass=ClassMetaclass):
    """Base class for all typed python Class objects."""
    pass