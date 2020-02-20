import unittest

from evaluate_policy.role import Role, InvalidRoleException


class TestRole(unittest.TestCase):
    def test_empty_role_load(self):
        with self.assertRaises(InvalidRoleException) as cm:
            Role.load("")

        invalid_role_exception = cm.exception
        self.assertEqual(invalid_role_exception.errors[0], "No role found")

