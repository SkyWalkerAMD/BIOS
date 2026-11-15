from pathlib import Path
import ast
H=Path(__file__).resolve().parent; original=H.parent/'native_observer04/build.py'
text=original.read_text().replace("H/'observer.c'","H/'observer05.c'").replace("H/'provider_calls.S'","H.parent/'native_observer04/provider_calls.S'").replace("H/'test_support.c'","H.parent/'native_observer04/test_support.c'").replace('W890NativeObserver04.TESTONLY.dll','W890NativeObserver05.TESTONLY.dll')
exec(compile(text,str(original),'exec'),{'__file__':str(__file__),'__name__':'__main__'})
