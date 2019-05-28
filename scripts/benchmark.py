#!/usr/bin/python
import argparse
import subprocess

from monotonic import monotonic

from detect_secrets.core.usage import PluginOptions


def main():
    flag_list = []
    args = get_arguments()

    # Fill flags list with PluginOptions flag text
    for flag_number, flag in enumerate(PluginOptions.all_plugins):
        flag_list.append(flag.disable_flag_text)

    # Run benchmarks for all the cases
    timings = {
        'all-plugins': time_execution([], args.filenames),
    }
    for flag_number, flag in enumerate(flag_list):
        plugins_to_ignore = list(flag_list)
        plugins_to_ignore.pop(flag_number)

        key = flag[len('--no-'):-len('-scan')]
        timings[key] = time_execution(plugins_to_ignore, args.filenames)

    print_output(timings, args.filenames)


def get_arguments():
    parser = argparse.ArgumentParser(description='Run some benchmarks.')
    parser.add_argument(
        'filenames',
        nargs=argparse.REMAINDER,
        help='Filenames to check or detect-secrets compatible arguments.',
    )

    args = parser.parse_args()
    if not args.filenames:
        args.filenames = ['../.']

    return args


def time_execution(flags, arguments):
    start_time = monotonic()
    subprocess.check_output('detect-secrets scan'.split() + arguments + flags)
    return monotonic() - start_time


def print_output(timings, filenames):
    """
    :type timings: dict
    """
    # Print header
    print('Scanning: ' + str(filenames))
    print('-' * 42)
    print('{:<20s}{:>20s}'.format('benchmark', 'time'))
    print('-' * 42)
    print_line('all-plugins', timings['all-plugins'])
    del timings['all-plugins']

    for key in sorted(timings):
        print_line(key, timings[key])


def print_line(name, time):
    print('{:<20s}{:>20s}s'.format(name, str(time)))


if __name__ == '__main__':
    main()
