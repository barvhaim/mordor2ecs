import json
from convert_func import raw_event_to_winlogbeat_event, convert_event

input_large_dataset_path = './mordor-master/datasets/large/apt29/day1/apt29_evals_day1_manual_2020-05-01225525.json'
output_large_dataset_path = './output_folder/output.json'
sample_size = 1000000


if __name__ == '__main__':
    with open(input_large_dataset_path, 'r') as fp:
        events_count = 0
        lines = fp.readlines()
        with open(output_large_dataset_path, 'w') as wp:
            for line in lines:
                evt = json.loads(line)
                evt = raw_event_to_winlogbeat_event(evt)
                evt = convert_event(evt)
                wp.write(json.dumps(evt) + "\n")
                if events_count > sample_size:
                    break
                events_count += 1