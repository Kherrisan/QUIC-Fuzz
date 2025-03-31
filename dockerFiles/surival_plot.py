import os
import json
import pandas as pd
import numpy as np
import argparse
from lifelines import KaplanMeierFitter
import matplotlib.pyplot as plt

def get_survival_data_table(report_json):
    with open(report_json, 'r') as file:
        json_data = json.load(file)

    data = []
    MAX_TRIAL_TIME = json_data['Trial-Time']
    trigger_count = {}

    for run, trials in json_data['Campaign'].items():
        for trial in trials:
            bug_id = trial['bug_id']
            
            if trial['triggered'] is not None:
                triggered_event_observed = 1  # Event occurred
                triggered_duration = trial['triggered']
                trigger_count[bug_id] = trigger_count.get(bug_id, 0) + 1
            else:
                triggered_event_observed = 0  # Event not occurred (censored)
                triggered_duration = MAX_TRIAL_TIME  # Censoring at max trial time

            if trial['reached'] is not None:
                reached_duration = trial['reached']
                reached_event_observed = 1  # Event occurred
            else:
                reached_duration = MAX_TRIAL_TIME  # Censoring at max trial time
                reached_event_observed = 0  # Event not reached (censored)

            data.append({
                'Target': json_data['Target'],
                'Fuzzer': json_data['Fuzzer'],
                'BugID': bug_id,
                'triggered_duration': triggered_duration,
                'triggered_event_observed': triggered_event_observed,
                'reached_duration': reached_duration,
                'reached_event_observed': reached_event_observed
            })

    df = pd.DataFrame(data)

    def fit_kmf(group, duration_col, event_col):
        kmf = KaplanMeierFitter()
        kmf.fit(group[duration_col], event_observed=group[event_col])
        return kmf

    # Create a list to store (bug_id, kmf) tuples
    kmf_triggered = []

    for (target, fuzzer, bug_id), group in df.reset_index().groupby(['Target', 'Fuzzer', 'BugID']):
        kmf = fit_kmf(group, 'triggered_duration', 'triggered_event_observed')
        kmf_triggered.append((bug_id, fuzzer, kmf))

    return kmf_triggered

def plot_kmf_survival_curves(kmf_triggered, output_folder):
    kmf_by_bug_id = {}

    row_max = 1
    column_max = 5
    row_count = 0
    column_count = 0

    kmf_triggered_sorted = sorted(kmf_triggered, key=lambda x: int(x[0][1:])) 

    fig, axes = plt.subplots(row_max, column_max, figsize = (20, 2.5))
    # sorted_subjects = sorted(mean_df['subject'].unique())
    
    # Organize the kmf objects by bug_id
    for bug_id, fuzzer, kmf in kmf_triggered_sorted:
        if bug_id not in kmf_by_bug_id:
            kmf_by_bug_id[bug_id] = []
        kmf_by_bug_id[bug_id].append((fuzzer, kmf))

    # Plot each bug_id in its own subplot
    is_first = 1
    for ax, (bug_id, kmf_list) in zip(axes, kmf_by_bug_id.items()):
        kmf_list_sorted = sorted(kmf_list, key=lambda x: x[0])

        counter = 0

        for fuzzer, kmf in kmf_list_sorted:
            line = kmf.plot_survival_function(ax=ax, label=fuzzer, marker='*', ci_alpha=0.1, ci_show=False, linewidth=3)

        # share y-axis label
        if(is_first != 1):
            ax.set_yticklabels([])

        is_first = 0
        ax.yaxis.set_tick_params(labelsize=14)
        ax.xaxis.set_tick_params(labelsize=14)
        ax.set_title(f'{bug_id}', fontweight='bold', fontsize=16)
        ax.set_xlabel('Time (seconds)').set_visible(False)
        ax.set_ylabel('Survival Probability').set_visible(False)
        ax.grid()

        ax.set_ylim(bottom=0)
        ax.set_xlim(right=172800)

        # Generate ticks every 21600 seconds up to 172800 seconds
        xticks_seconds = list(range(0, 172801, 21600))
        ax.set_xticks(xticks_seconds)

        # Convert seconds to hours for labels
        xticks_hours = [tick / 3600 for tick in xticks_seconds]
        ax.set_xticklabels([f"{int(hour)}" for hour in xticks_hours])

        # # Generate ticks every 21600 up to 172800
        # xticks = list(range(0, 172801, 43200))
        # ax.set_xticks(xticks)

        # Set white background for the plot area
        ax.set_facecolor('white')
        # Remove plot outline by making spines invisible
        for spine in ax.spines.values():
            spine.set_visible(False)
        
        # Add a legend for each subplot
        # ax.legend(title='Fuzzer', loc='best')
        ax.legend().set_visible(False)

    # Set white background for the whole figure
    fig.patch.set_facecolor('white')
    plt.subplots_adjust(bottom=0.38, wspace=0.1)

    fig.supxlabel('Time (hours)', y=0.18, fontsize=14)
    fig.supylabel('Survival Probability', x=0.093, fontsize=14)

    legend_list = ['AFLNet', 'ChatAFL', 'Fuzztruction-Net', 'QUIC-Fuzz (Ours)']
    
    legend = fig.legend(legend_list, loc='lower center', bbox_to_anchor=(0.5, -0.025), ncol=5, handlelength=2, handleheight=1.5, markerscale=1.5, fontsize=18, frameon=False)

    for text in legend.get_texts():
        if text.get_text() == 'QUIC-Fuzz (Ours)':
            text.set_fontweight('bold')

    # Save the combined figure with all subplots
    plt.savefig(os.path.join(output_folder, 'combined_survival_plot_by_bug_id.pdf'), bbox_inches='tight', facecolor='white') #bbox_inches='tight',
    

    # # Plotting for each bug_id
    # for bug_id, kmf_list in kmf_by_bug_id.items():
    #     # plt.figure(figsize=(10, 6))
        
    #     for fuzzer, kmf in kmf_list:
    #         kmf.plot_survival_function(label=fuzzer, ci_alpha=0.1, ci_show=False)

    #     plt.title(f'{bug_id} Survival Time')
    #     plt.xlabel('Time (seconds)')  # Set label back to seconds
    #     plt.ylabel('Survival Probability')

    #     # No conversion for x-ticks since we're back to seconds
    #     plt.legend(title='Fuzzer')
    #     plt.grid()

    #     # Set white background
    #     plt.gcf().patch.set_facecolor('white')
    #     plt.gca().set_facecolor('white')

    #     # Remove the plot outline by making spines invisible
    #     for spine in plt.gca().spines.values():
    #         spine.set_visible(False)

    #     # Save the plot with a white background
    #     plt.savefig(os.path.join(output_folder, f'survival_plot_bug_{bug_id}.png'), bbox_inches='tight', facecolor='white')
    #     # plt.savefig(os.path.join(output_folder, f'survival_plot_bug_test.png'), bbox_inches='tight', facecolor='white')
    #     plt.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Calculate bug statistics from JSON data.')
    parser.add_argument('reports_folder', type=str, help='Path to reports file containing bug data.')
    
    args = parser.parse_args()
    reports_folder = args.reports_folder
    output_folder = "survival_plots"
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    kmf_triggered = []  

    for filename in os.listdir(reports_folder):
        if filename.endswith('.json'):
            file_path = os.path.join(reports_folder, filename)
            kmf_data = get_survival_data_table(file_path)  
            kmf_triggered.append(kmf_data)  

    kmf_triggered_flattened = [kmf for kmf_group in kmf_triggered for kmf in kmf_group]
    plot_kmf_survival_curves(kmf_triggered_flattened, output_folder)