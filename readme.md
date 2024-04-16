# AgentSmith

Easter 2024 pet project :)

Performs network isolation that only Neo can control.

He either allows everyone to talk, restricts network access to only him or Trinity too.

To use, start 3 Admin terminals and run Neo.exe, Trinity.exe and AgentSmith.exe respectively.

All instances immediately start polling some trivial remote endpoint which just returns our current remote IP.
Any instance may be terminated by pressing 'x'.

Neo understand these keys:
'i': 'isolate' the endpoint so that only Neo can continue communicating.
'e': 'extended isolate' so that in addition to Neo, Trinity may also communicate.
'f': 'free' the endpoint again, so that even Agent Smith may communicate.

Of course not only Agent Smith gets isolated but the entire endpoint.

Stuff is implemented using Windows Filering Platform (WFP).
