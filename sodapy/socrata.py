try:
    from warnings import deprecated
except ImportError:
    from typing_extensions import deprecated

from sodapy.sodapy import Sodapy


@deprecated("Use the Sodapy class instead")
class Socrata(Sodapy):
    pass
