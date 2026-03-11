#!/usr/bin/env python3
"""semgrep_lite - Simple pattern matcher for code. Zero deps."""
import sys,re,os
def main():
    if len(sys.argv)<3:print('Usage: semgrep_lite.py <pattern> <path> [--ext .py]');sys.exit(1)
    pat=re.compile(sys.argv[1]);path=sys.argv[2]
    ext=sys.argv[sys.argv.index('--ext')+1] if '--ext' in sys.argv else None
    n=0
    for r,_,fs in os.walk(path):
        for f in fs:
            if ext and not f.endswith(ext):continue
            fp=os.path.join(r,f)
            try:
                for i,line in enumerate(open(fp),1):
                    if pat.search(line):print(f'{fp}:{i}: {line.rstrip()}');n+=1
            except:pass
    sys.stderr.write(f'{n} matches\n')
if __name__=='__main__':main()
