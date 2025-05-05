from warnings import deprecated
from sodapy.sodapy import Sodapy


@deprecated("Use the Sodapy class instead")
class Socrata(Sodapy):
    pass
