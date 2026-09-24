# The sabotage test, recorded with vhs (https://github.com/charmbracelet/vhs):
#   vhs demo/sabotage.tape
# A healthy setup is reported healthy. Then exactly one thing is broken --
# the execute bit on the guard -- and the report names exactly that one.

Output demo/sabotage.gif

Set Shell bash
Set FontSize 14
Set Width 1240
Set Height 500
Set Padding 18
Set TypingSpeed 45ms
Set Theme "Catppuccin Mocha"

Hide
Type "rm -rf /tmp/hookprobe-demo && cp -R demo/project /tmp/hookprobe-demo && export PYTHONPATH=$PWD/src PATH=$PWD/demo/bin:$PATH && cd /tmp/hookprobe-demo && export PS1='$ ' && clear"
Enter
Sleep 1s
Show

Type "hookprobe . --no-home"
Enter
Sleep 5s

Hide
Type "clear"
Enter
Show

Type "chmod -x .claude/hooks/guard.py"
Enter
Sleep 1.5s

Type "hookprobe . --no-home"
Enter
Sleep 8s
