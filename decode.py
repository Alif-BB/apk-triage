strings = [
    "q~tb\x7fyt>s\x7f~du~d>`}>@qs{qwu@qbcub4@qs{qwu",
    "q~tb\x7fyt>q``>QsdyfydiDxbuqt",
    "sebbu~dQsdyfydiDxbuqt",
    "}Xyttu~Q`yGqb~y~wCx\x7fg~",
    "wud@b\x7fsucc^q}u"
]

for s in strings:
    decoded = ''.join(chr(ord(c) ^ 16) for c in s)
    print(f"{s!r} => {decoded}")