#!/usr/bin/env python

# This code is taken from profuzzbench/scripts/analysis/profuzzbench_plot.py with minor modification

import argparse
from pandas import read_csv
from pandas import DataFrame
from pandas import Grouper
from matplotlib import pyplot as plt
import pandas as pd


def main(csv_file, put, runs, cut_off, step, out_file):
  #Read the results
  df = read_csv(csv_file)

  #Calculate the mean of code coverage
  #Store in a list first for efficiency
  mean_list = []

  fuzzer_not_found = []

  for subject in put:
    print(f"Processing subject: {subject}")

    if((df['subject'] == subject).sum() == 0):  
      print("Subject: " + subject + " not found.")
      continue

    for fuzzer in ['aflnet', 'chatafl', 'fuzztruction-net', 'quic-fuzz']:
    # for fuzzer in ['aflnet', 'quic-aflnet', 'quic-fuzz-nosnap', 'quic-fuzz']:
      if((df['fuzzer'] == fuzzer).sum() == 0):
        print("   Fuzzer: " + fuzzer + " not found.")
        fuzzer_not_found.append(fuzzer)
        continue

      for cov_type in ['b_abs']:
        if((df['cov_type'] == cov_type).sum() == 0):
          continue

        #get subject & fuzzer & cov_type-specific dataframe
        df1 = df[(df['subject'] == subject) & 
                         (df['fuzzer'] == fuzzer) & 
                         (df['cov_type'] == cov_type)]

        mean_list.append((subject, fuzzer, cov_type, 0, 0.0, 0.0, 0.0))

        for time in range(1, cut_off + 1, step):
          cov_total = 0
          run_count = 0
          cov_max = 0
          cov_min = 0
          cov_values = []

          for run in range(1, runs + 1, 1):
            #get run-specific data frame
            df2 = df1[df1['run'] == run]

            if df2.empty:
              # print(f"      No data available for run {run} in {subject} of {fuzzer}")
              continue

            #get the starting time for this run
            start = df2.iloc[0, 0]

            #get all rows given a cutoff time
            if(fuzzer != "fuzztruction-net"):
              df3 = df2[df2['time'] <= start + time*60]
            else:
              # fuzztruction-net uses ms
              df3 = df2[df2['time'] <= time*60*1000]
              if df3.empty:
                continue
            
            #update total coverage and #runs
            cov_total += float(df3.tail(1).iloc[0, 5].strip('%'))
            cov_values.append(float(df3.tail(1).iloc[0, 5].strip('%')))
            run_count += 1

            # if(cov_type == 'b_abs'):
            #   print("cov is" + str(df3.tail(1).iloc[0, 5].strip('%')))

            if(cov_max == 0 and cov_min == 0):
              cov_max = float(df3.tail(1).iloc[0, 5].strip('%'))
              cov_min = float(df3.tail(1).iloc[0, 5].strip('%'))
            elif(cov_max < float(df3.tail(1).iloc[0, 5].strip('%'))):
              cov_max = float(df3.tail(1).iloc[0, 5].strip('%'))
            elif(cov_min > float(df3.tail(1).iloc[0, 5].strip('%'))):
              cov_min = float(df3.tail(1).iloc[0, 5].strip('%'))
            
            if(time == cut_off):
              print("0," + fuzzer + "," + subject + "," + str(run-1) + "," + str(df3.tail(1).iloc[0, 5].strip('%')))

          median_cov = pd.Series(cov_values).median()

          # if(time == cut_off):
            # print("last mediam coverage for " + fuzzer + " " + subject + " is " + str(median_cov))
            # print(" best coverage for " + fuzzer + " " + subject + " is " + str(cov_max))
            # print(" worst coverage for " + fuzzer + " " + subject + " is " + str(cov_min))

          #add a new row
          # mean_list.append((subject, fuzzer, cov_type, time, cov_total / run_count, cov_max, cov_min))

          # median
          mean_list.append((subject, fuzzer, cov_type, time, median_cov/1000, cov_max/1000, cov_min/1000))
          # if(cov_type == 'b_abs'):
          #   print("median is " + str((cov_min + cov_max)/2) + "\n\n")

  #Convert the list to a dataframe
  mean_df = pd.DataFrame(mean_list, columns = ['subject', 'fuzzer', 'cov_type', 'time', 'cov', 'cov_max', 'cov_min'])

  row_max = 2
  column_max = 3
  row_count = 0
  column_count = 0

  fig, axes = plt.subplots(row_max, column_max, figsize = (20, 10))
  sorted_subjects = sorted(mean_df['subject'].unique())

  # print(sorted_subjects)

  # color_map = {
  #   'QUIC-Fuzz (Ours)': 'red',
  #   'aflnet': 'blue',
  #   'chatafl': 'orange',
  #   'fuzztruction-net': 'green'
  # }

  for subject in sorted_subjects:
    subject_df = mean_df[mean_df['subject'] == subject]

    # print(subject + "column: " + str(column_count) + "row: " + str(row_count))

    for key, grp in subject_df.groupby(['fuzzer', 'cov_type']):
      label_name = key[0]

      # if(label_name == 'quic-fuzz'):
        # label_name = 'QUIC-Fuzz (Ours)'

      # Set color based on the fuzzer name
      # line_color = color_map.get(label_name, 'black')  # Default to black if not found

      if key[1] == 'b_abs':
        axes[row_count, column_count].plot(grp['time'], grp['cov'] , marker='*', markevery=250, label=label_name, linewidth=4) #, marker='o', linestyle='-'
        axes[row_count, column_count].fill_between(grp['time'], grp['cov_max'], grp['cov_min'], alpha=0.15, label="_nolegend_")
        axes[row_count, column_count].yaxis.set_tick_params(labelsize=18) 
        axes[row_count, column_count].xaxis.set_tick_params(labelsize=18) 
        axes[row_count, column_count].set_xlabel('Time (in min)', fontsize=18)
        axes[row_count, column_count].set_ylabel('#Branches (in thousands)', fontsize=18)

    if(subject == "google_quiche"):
      axes[row_count, column_count].set_title("google-quiche", fontweight='bold', fontsize=22)
    elif(subject == "xquic"):
      axes[row_count, column_count].set_title("xquic (ae6f7f7)", fontweight='bold', fontsize=22)
    else:
      axes[row_count, column_count].set_title(f"{subject}", fontweight='bold', fontsize=22)

    if(column_count + 1 == column_max):
      row_count += 1
      column_count = 0

      if(row_count == row_max):
        break

    else:
      column_count += 1

  for i, ax in enumerate(fig.axes):
    ax.grid()

  # plt.rcParams['text.usetex'] = True

  legend_list = []

  # Note: the legend need to follow fuzers alphabetical order.

  if('aflnet' not in fuzzer_not_found):
    legend_list.append('AFLNet')

  if('chatafl' not in fuzzer_not_found):
    legend_list.append('ChatAFL')

  if('fuzztruction-net' not in fuzzer_not_found):
    legend_list.append('Fuzztruction-Net')

  if('quic-fuzz' not in fuzzer_not_found):
    # legend_list.append(r'$\bf{QUIC\text{-}Fuzz\ (ours)}$')
    legend_list.append('QUIC-Fuzz (Ours)')
  
  # if('quic-aflnet' not in fuzzer_not_found):
  #   legend_list.append('QUIC-AFLNet')

  # if('quic-fuzz-nosnap' not in fuzzer_not_found):
  #   legend_list.append('QUIC-Fuzz-noSnap')

  legend = fig.legend(legend_list, loc='lower center', ncol=6, handlelength=3, handleheight=2, markerscale=3, fontsize=24, frameon=False)

  for text in legend.get_texts():
    if text.get_text() == 'QUIC-Fuzz (Ours)':
        text.set_fontweight('bold')

  plt.subplots_adjust(top=0.95, hspace=0.30, bottom=0.15)
  # plt.subplots_adjust(bottom=0.92)
  
  #Save to file
  plt.savefig(out_file, format="pdf")

# Parse the input arguments
if __name__ == '__main__':
    parser = argparse.ArgumentParser()    
    parser.add_argument('-i','--csv_file',type=str,required=True,help="Full path to results.csv")
    parser.add_argument('-p','--put',type=str,nargs='+',required=True,help="Name of the subject programs")
    parser.add_argument('-r','--runs',type=int,required=True,help="Number of runs in the experiment")
    parser.add_argument('-c','--cut_off',type=int,required=True,help="Cut-off time in minutes")
    parser.add_argument('-s','--step',type=int,required=True,help="Time step in minutes")
    parser.add_argument('-o','--out_file',type=str,required=True,help="Output file")
    args = parser.parse_args()
    main(args.csv_file, args.put, args.runs, args.cut_off, args.step, args.out_file)
