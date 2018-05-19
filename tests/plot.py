#
# This module ingests stats from Monitor in setup module
# and generates graphs for avg deflate latency, avg block
# allocation latency
#
import Gnuplot

def PlotData(title, xlabel, ylabel, x, y):
    g = Gnuplot.Gnuplot()
    g.title(title)
    g.xlabel(xlabel)
    g.ylabel(ylabel)
    g("set grid")
    d = Gnuplot.Data (x, y, with_="lines")
    g.plot(d)
    return g

def GetY(fileName, colNo):
    y = []
    with open(fileName, 'r') as f:
        lines = f.readlines()
        for line in lines:
            data = line.split()
            y.append(int(data[colNo]))
    return y

#Plot deflate statistics
y = GetY('/tmp/data', 7)
x = range(1, len(y) + 1)
g = PlotData("deflate stats", "time(sec)", "latency(nsec)", x, y)
g.hardcopy (filename='/tmp/plot_deflate.png', terminal='png')

#Plot balloc statistics
y = GetY('/tmp/data', 4)
x = range(1, len(y) + 1)
g = PlotData("balloc stats", "time(sec)", "latency(nsec)", x, y)
g.hardcopy (filename='/tmp/plot_balloc.png', terminal='png')
diff --git a/tests/setup.py b/tests/setup.py
