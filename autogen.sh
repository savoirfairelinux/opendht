test -f AUTHORS || touch AUTHORS
test -f ChangeLog || touch ChangeLog
test -f NEWS || touch NEWS
test -f README || cp -f README.md README
autoreconf --install --verbose -Wall