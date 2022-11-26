#!/bin/sh
cat $1 | grep stat | awk '{print $10 " " $11 " " $12 " "$13}' | awk 'BEGIN{ min = 65535} {if ($4 < min) {min = $4}} END{printf "Min = %.1f\n",min}'
cat $1 | grep stat | awk '{print $10 " " $11 " " $12 " "$13}' | awk 'BEGIN{ max = 0} {if ($4 > max) {max = $4}} END{printf "Max = %.1f\n",max}'
cat $1 | grep stat | awk '{print $10 " " $11 " " $12 " "$13}' | awk '{sum += $4} END {printf "Average = %3.3f\nNR = %d\n",sum/NR,NR}'
