if [ -f er ];
then
	rm er
fi
for j in 60 55 50 45 40;do for((i=1;i<=20;i=i+1));do echo '****'>>er1;./scripts/tdis -n $j -d $j ../experiments/toc-all/log/connected-3.mal-0.nodes-$j.$i>er;cat er|wc -l>>er1;sort -n er|tail -1>>er1;sort -n er|head -1 >>er1;done;done

for j in 60 55 50 45 40;do for((i=1;i<=20;i=i+1));do echo '****'>>er2;./scripts/tdis -n $j -d $j ../experiments/toc-one/log/connected-3.mal-0.nodes-$j.$i>er;cat er|wc -l>>er2;sort -n er|tail -1>>er2;sort -n er|head -1 >>er2;done;done

for j in 60 55 50 45 40;do for((i=1;i<=20;i=i+1));do echo '****'>>er3;./scripts/tdis -n $j -d $j ../experiments/toc-one/log/connected-3.mal-1.nodes-$j.$i>er;cat er|wc -l>>er3;sort -n er|tail -1>>er3;sort -n er|head -1 >>er3;done;done
