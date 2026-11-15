"""Fixed-image orchestration of independently checked legacy framing plans."""
from hdmedia_offline import IUSBEngine,Reject,PINNED_SHA256,PINNED_SIZE
from review_legacy_data.bounded_legacy import bind_session,normalize_request,serialize_response,Reject as FramingReject

class ObservedSessionEngine(IUSBEngine):
    def __init__(self,factory):
        super().__init__(factory)
        self.session=None;self.legacy_commands=0;self.reserved_write_bytes=0
        self.padding_counts={};self.opaque_direction_counts={};self.action_counts={}
        self.last_plan=None

    def stop(self):
        self.session=None
        super().stop()

    def handle(self,frame):
        try:
            if self.state=='AUTH_PENDING':
                # Called only by the connector after exact peer-certificate and
                # tunnel checks. Binding validates the observed F1 success form.
                session=bind_session(frame,tls_verified=True,authenticated=True,
                                     image_sha256=PINNED_SHA256,image_bytes=PINNED_SIZE)
                self.image=self.factory()  # Independently validates+locks actual file.
                self.session=session;self.instance=frame[23];self.state='ACTIVE'
                return None
            if self.state!='ACTIVE' or self.session is None:raise Reject('inactive image session')
            plan=normalize_request(self.session,frame)
            # Reserve before all backend effects; any failure closes rather than retries.
            self.session=plan.next_session
            self.legacy_commands+=1;self.reserved_write_bytes=self.session.reserved_write_bytes
            for counts,value in [(self.padding_counts,plan.padding_kind),
                                 (self.opaque_direction_counts,str(plan.opaque_direction)),
                                 (self.action_counts,plan.action)]:
                counts[value]=counts.get(value,0)+1
            self.last_plan={'opcode':f'{plan.opcode:02X}','action':plan.action,'lba':plan.lba,
                            'count':plan.count,'padding_kind':plan.padding_kind}
            data=None
            if plan.action=='read':data=self.image.read(plan.lba,plan.count)
            elif plan.action=='write':self.image.write(plan.lba,plan.count,plan.write_data)
            elif plan.action=='flush':self.image.flush()
            elif plan.action not in ('control','reply_then_stop','stop_without_reply'):
                raise Reject('unknown planned backend action')
            response=serialize_response(plan,data)
            if plan.action in ('reply_then_stop','stop_without_reply'):self.stop()
            return response
        except FramingReject as error:
            self.stop();raise Reject(str(error)) from None
        except Exception:
            self.stop();raise
