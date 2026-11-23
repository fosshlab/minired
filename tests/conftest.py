import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from utiles import lab_3pc  # noqa: E402
from minired.modelo.a_mininet import planificar  # noqa: E402


@pytest.fixture
def plan_3pc():
    return planificar(lab_3pc())
