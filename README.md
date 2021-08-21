### LSASS Dumping With Foreign Handles

You must be admin or system, blah blah blah.

build with:
```
	x86_64-w64-mingw32-gcc -c foreign_lsass.c -o foreign_lsass.x64.o
	i686-w64-mingw32-gcc -c foreign_lsass.c -o foreign_lsass.x86.o
```

Sources:
ngl please don't judge my old (and current) awful code

https://github.com/alfarom256/lsassdump

https://skelsec.medium.com/duping-av-with-handles-537ef985eb03
