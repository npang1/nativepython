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

from typed_python import *
import typed_python._types as _types
from nativepython.runtime import Runtime
import unittest
import time

def Compiled(f):
    f = TypedFunction(f)
    return Runtime.singleton().compile(f)

class TestCompilationStructures(unittest.TestCase):
    def checkFunctionOfIntegers(self, f):
        r  = Runtime.singleton()

        f_fast = r.compile(f)

        for i in range(100):
            self.assertEqual(f_fast(i), f(i))

    def test_simple_loop(self):
        def f(x: int) -> int:
            y = 0
            while x > 0:
                x = x - 1
                y = y + x
            return y

        self.checkFunctionOfIntegers(f)

    def test_returning(self):
        def f(x: int) -> int:
            return x

        self.checkFunctionOfIntegers(f)

    def test_basic_arithmetic(self):
        def f(x: int) -> int:
            y = x+1
            return y

        self.checkFunctionOfIntegers(f)

    def test_boolean_operators(self):
        @Compiled
        def f(x: int, y: int, z: int) -> bool:
            return x and y and z

        self.assertEqual(f(0,1,1), False)
        self.assertEqual(f(0,0,1), False)
        self.assertEqual(f(0,0,0), False)
        self.assertEqual(f(1,0,0), False)
        self.assertEqual(f(1,1,0), False)
        self.assertEqual(f(1,1,1), True)

    def test_object_to_int_conversion(self):
        @Compiled
        def f(x: int) -> int:
            return int(object(x))

        self.assertEqual(f(10), 10)

    def test_variable_type_changes_make_sense(self):
        @Compiled
        def f(x: int) -> float:
            y = x
            y = 1.2
            return y

        self.assertEqual(f(10), 1.2)

    def test_call_other_typed_function(self):
        def g(x: int) -> int:
            return x+1

        def f(x: int) -> int:
            return g(x+2)

        self.checkFunctionOfIntegers(f)

    def test_call_untyped_function(self):
        @TypedFunction
        def f(x):
            return x

        Runtime.singleton().compile(f)

        x = []

        self.assertIs(f(x), x)

    def test_call_other_untyped_function(self):
        def g(x):
            return x

        @TypedFunction
        def f(x):
            return g(x)

        Runtime.singleton().compile(f)

        x = []

        self.assertIs(f(x), x)

    def test_integers_in_closures(self):
        y = 2
        def f(x: int) -> int:
            return x+y

        self.checkFunctionOfIntegers(f)

    def test_loop_variable_changing_type(self):
        @Compiled
        def f(top: float) -> OneOf(int, float):
            y = 0
            x = 0
            while x < top:
                x += 1.0
                y += x

            return y

        self.assertEqual(f(3.5), 10.0)

    def test_unassigned_variables(self):
        @Compiled
        def f(switch: int, t: TupleOf(int)) -> TupleOf(int):
            if switch:
                x = t
            return x

        self.assertEqual(f(1, (1,2,3)), (1,2,3))

        with self.assertRaisesRegex(Exception, "local variable 'x' referenced before assignment"):
            self.assertEqual(f(0, (1,2,3)), (1,2,3))

    def test_return_from_function_without_return_value_specified(self):
        @Compiled
        def f(t: TupleOf(int)):
            return t

        self.assertEqual(f((1,2,3)), (1,2,3))

    def test_return_from_function_with_bad_convert_throws(self):
        @Compiled
        def f(t: TupleOf(int)) -> None:
            return t

        with self.assertRaisesRegex(Exception, "Can't convert"):
            f((1,2,3))

    def test_mutually_recursive_untyped_functions(self):
        def q(x):
            return x-1

        def z(x):
            return q(x)+1

        def f(x):
            return z(g(x - 1)) + z(g(x - 2)) + z(x)

        def g(x):
            if x > 0:
                return z(f(x-1)) * z(2) + f(x-2)
            return 1

        g_typed = TypedFunction(g)

        Runtime.singleton().compile(g_typed, {'x': int})
        Runtime.singleton().compile(g_typed, {'x': float})

        self.assertEqual(g(10), g_typed(10))

        t0 = time.time()
        g(18)
        untyped_duration = time.time() - t0


        t0 = time.time()
        g_typed(18)
        typed_duration = time.time() - t0

        #I get around 50x.
        speedup = untyped_duration / typed_duration
        self.assertGreater(speedup, 20)





