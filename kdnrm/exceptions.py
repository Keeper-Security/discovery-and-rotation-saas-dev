from typing import Optional


class KdrnmException(Exception):

    def __init__(self,
                 msg,
                 other_msg: Optional[str] = None,
                 skip_post_cleanup: Optional[bool] = False,
                 skip_msg_prepend: Optional[bool] = False,
                 notes: Optional[str] = None,
                 code: Optional[str] = None,
                 values: Optional[dict] = None):

        if isinstance(msg, str) is False:
            msg = str(msg)

        if other_msg is not None and isinstance(other_msg, str) is False:
            other_msg = str(other_msg)

        self.msg = msg
        self.other_msg = other_msg
        self.skip_post_cleanup = skip_post_cleanup
        self.skip_msg_prepend = skip_msg_prepend
        self.notes = notes

        if values is None:
            values = {}
        if isinstance(values, dict) is False:
            raise Exception("The param values needs to be a dictionary.")

        self._codes = [
            {
                "msg": msg,
                "code": code or msg,
                "values": values
            }
        ]

        super().__init__(self.msg)

    def __str__(self):
        return self.msg

    @property
    def codes(self):
        return self._codes


class SaasException(KdrnmException):
    """
    Exception in the SaaS post rotation
    """
    pass
