"""One bounded post-auth legacy compatibility step; disk parser stays strict."""
from hdmedia_offline import Reject
from observed_auth_adapter import ObservedAuthEngine
from review_legacy_frames.legacy_tur_once import respond_once,LegacyTurReject

class ObservedSessionEngine(ObservedAuthEngine):
    def __init__(self,factory):
        super().__init__(factory)
        self.auth_reply=None
        self.legacy_tur_replies=0
        self.first_ordinary_header_matches_auth=None

    def stop(self):
        self.auth_reply=None
        super().stop()

    def handle(self,frame):
        try:
            if self.state=='AUTH_PENDING':
                response=super().handle(frame)
                if self.state=='ACTIVE' and frame[8:11]==b'\0\0\0':
                    self.auth_reply=frame
                return response
            if self.auth_reply is not None:
                auth=self.auth_reply
                self.auth_reply=None
                self.first_ordinary_header_matches_auth=frame[:32]==auth[:32]
                if frame[8:11]==b'\0\0\0':
                    try:
                        reply=respond_once(auth,frame,authenticated=self.state=='ACTIVE',consumed=False)
                    except LegacyTurReject as error:
                        raise Reject(str(error)) from None
                    assert reply.consumed and not reply.opens_or_touches_image and not reply.permits_other_legacy_frames
                    self.legacy_tur_replies+=1
                    # Keep only this actually sent response in the serializer's
                    # retained buffer, never authentication data or old padding.
                    self.writer.buffer[:]=bytes(len(self.writer.buffer))
                    self.writer.buffer[:len(reply.response)]=reply.response
                    return reply.response
            return super().handle(frame)
        except Exception:
            self.stop()
            raise
