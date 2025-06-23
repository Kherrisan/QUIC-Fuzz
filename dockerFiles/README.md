# Experiment using Docker
We provide detailed instructions in each ```./<server_name>/README.md``` to run the fuzzing individually. To fuzz QUIC servers using Fuzztruction-Net, please refer to [./Fuzztruction-Net_QUIC_experiment](Fuzztruction-Net_QUIC_experiment).


## Analysis
After the experiment is completed, we use ```./profuzzbench_generate.csv.sh``` and ```./profuzzbench_plot.py``` to generate coverage graph.<br/>
For example:
```bash
# generate results.csv
# ./profuzzbench_generate_csv.sh <server_name> <number_of_runs> <fuzzer_name> <csv_output> <append_csv_output?>
./profuzzbench_generate_csv.sh quicly 5 quic-fuzz results.csv 0

# generate plot
# python3 profuzzbench_plot.py -i <csv_file> -p <server_name> -r <number_of_runs> -c <time_in_minutes> -s <plot_every_N_step> -o <output>
python3 profuzzbench_plot.py -i results.csv -p quicly -r 5 -c 60 -s 1 -o quicly_60_minites_coverage.png

python3 ../dockerFiles/profuzzbench_plot_for_6.py -i all_cov.csv -p google_quiche lsquic ngtcp2 picoquic quicly xquic -r 10 -c 2880 -s 1 -o all_cov.pdf
```

## Build all docker container
The commands below will build all the container, to see specific command for each subject (implementation), please see ```./<subject_name>/README.md```
```bash
# include your OpenAI API key in this file
echo <your-key> > ~/.openai_key

cd lsquic
docker build --build-arg OPENAI_API_KEY="$(cat ~/.openai_key)" -t lsquic . --no-cache && cd ../google_quiche/ && docker build --build-arg OPENAI_API_KEY="$(cat ~/.openai_key)" -t google_quiche . --no-cache && cd ../ngtcp2 && docker build --build-arg OPENAI_API_KEY="$(cat ~/.openai_key)" -t ngtcp2 . --no-cache && cd ../picoquic/ && docker build --build-arg OPENAI_API_KEY="$(cat ~/.openai_key)" -t picoquic . --no-cache && cd ../quicly/ && docker build --build-arg OPENAI_API_KEY="$(cat ~/.openai_key)" -t quicly . --no-cache &&  cd ../xquic/ && docker build --build-arg OPENAI_API_KEY="$(cat ~/.openai_key)" -t xquic . --no-cache

cd msquic
docker build --build-arg OPENAI_API_KEY="$(cat ~/.openai_key)" -t msquic . --no-cache && cd ../mvfst/ && docker build --build-arg OPENAI_API_KEY="$(cat ~/.openai_key)" -t mvfst . --no-cache && cd ../neqo && docker build --build-arg OPENAI_API_KEY="$(cat ~/.openai_key)" -t neqo . --no-cache && cd ../quiche/ && docker build --build-arg OPENAI_API_KEY="$(cat ~/.openai_key)" -t quiche . --no-cache && cd ../quinn/ && docker build --build-arg OPENAI_API_KEY="$(cat ~/.openai_key)" -t quinn . --no-cache &&  cd ../s2n-quic/ && docker build --build-arg OPENAI_API_KEY="$(cat ~/.openai_key)" -t s2n-quic . --no-cache
```