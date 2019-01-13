import collections

def addrs(line):
    return line.split(":")[2].strip()


def payload(line):
    return int(line.strip().split()[-1])

def get_totals(lines):
    totals = dict()
    for line in lines:
        a = addrs(line)
        p = payload(line)
        (running, loads) = totals.get(a, (0, []))
        running += p
        loads.append(p)
        totals[a] = (running, loads)
    out = dict()
    for (k, (running, loads)) in totals.items():
        c = collections.Counter(loads)
        median = sorted((size, ct) for size, ct in c.items(), key=lambda x: x[-1], reverse=True)[0]
        out[k] = (running, median)
    return out


best = sorted((
    (k, (running, median))
     for (k, (running, median)) in totals.items()),
               key=lambda x: x[1][0],
               reverse=True)[:100]

def maybe_host(i):
    try:
        return socket.gethostbyaddr(i)[0]
    except:
        return 'err'

h_totals = [(maybe_host(i), (size, ct)) for i, (size, ct) in best]


disk = 923795456

# ls -l gets you the above
# ls -lh: 881M

disk / 2 ** 20
# 881.0 so I think this is how i report MB

h_totals[:10]

big = [(h, s) for (h, (s, (median, ct))) in h_totals if median >= 1400]

n_big = [s for h, s in big]

sum(s for s in sorted(n_big)[6:]) / 2 ** 30


from pprint import pprint as pp

def main():
    with open("output.txt") as f:
        totals = get_totals(f.readlines())
    pp(totals)

if __name__ == '__main__':
    main()
