#!/usr/bin/env python3
# Copyright 2017 Stanislaw Pitucha
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import os
from collections import defaultdict, namedtuple
import re
import argparse


erb_func = re.compile('_erb_+\\d+_\\d+')
module_ptr = re.compile('Module:0x[0-9a-f]+')

SINKS = [
        {
            'match': 'Rack::MockRequest.parse_uri_rfc2396',
            'name': 'MockRequest parsing',
        },
        {
            'match': 'I18n::Backend::Base#load_translations',
            'name': 'loading translations',
        },
        {
            'match': 'ActionView::Resolver#find_all',
            'name': 'ActionView finding templates',
            },
        {
            'match': 'ActionDispatch::Journey::Router#find_routes',
            'name': 'ActionDispatch building route cache',
            },
        {
            'match': 'ActiveSupport::Dependencies::Loadable#require',
            'name': 'ActiveSupport dependency loading',
            },
        {
            'match': 'ActiveSupport::Dependencies#load_missing_constant',
            'name': 'ActiveSupport dependency loading',
            },
        {
            'match': 'AbstractController::Base.action_methods',
            'name': 'ActionPack caching action methods',
            },
        {
            'match': 'AbstractController::UrlFor::ClassMethods#action_methods',
            'name': 'ActionPack caching action methods (UrlFor)',
            },
        {
            'match': 'NewRelic::Agent::Agent::InstanceMethods#connect',
            'name': 'NewRelic agent instance methods initialisation',
            },
        {
            'match': 'NewRelic::Agent::NewRelicService#connect',
            'name': 'NewRelic agent service connection',
            },
        {
            'match': 'ActionDispatch::Cookies::SignedCookieJar#initialize',
            'name': 'ActionDispatch cookie jar initialisation',
            },
        {
            'match': 'ActionDispatch::Cookies::EncryptedCookieJar#initialize',
            'name': 'ActionDispatch cookie jar initialisation',
            },
        {
            'match': 'ActionDispatch::Routing::RouteSet#url_helpers',
            'name': 'ActionDispatch caching url helpers',
            },
        {
            'match': 'ActionDispatch::Routing::RouteSet#url_for',
            'name': 'ActionDispatch caching url for',
            },
        {
            'match': 'ActionView::Template#compile!',
            'name': 'ActionView template compilation',
            },
        {
            'match': 'Datadog::Statsd#initialize',
            'name': 'Datadog initialisation',
            },
        {
            'match': 'ActiveRecord::ConnectionAdapters::SchemaCache#columns',
            'name': 'ActiveRecord caching table schemas',
            },
        {
            'match': 'ActiveRecord::AttributeMethods::ClassMethods#define_attribute_method',
            'name': 'ActiveRecord creating attribute methods on models',
            },
        {
            'match': 'ActiveRecord::Calculations',
            'name': 'application initiated queries',
            },
        {
            'match': 'ActiveRecord::Querying',
            'name': 'application initiated queries',
            },
        {
            'match': 'ActiveRecord::Relation',
            'name': 'application initiated queries',
            },
        ]


def parse_args():
    parser = argparse.ArgumentParser(description="Process stack traces")
    parser.add_argument('-u', '--unify-traces', action='store_true', default=False)
    parser.add_argument('-m', '--common-middleware', action='store_true', default=False)
    parser.add_argument('-k', '--known-sinks', action='store_true', default=False)
    parser.add_argument('-f', '--files-only', action='store_true', default=False)
    parser.add_argument('-v', '--verbose', action='store_true', default=False)
    parser.add_argument('-o', '--other-count', action='store', type=int, default=5)
    parser.add_argument('-l', '--other-length', action='store', type=int, default=30)
    parser.add_argument('-t', '--templates', action='store_true', default=False)
    parser.add_argument('STACKS_DIR')
    return parser.parse_args()


def unify_traces(options, traces):
    pre_count = len(traces)

    to_check = list(sorted(traces.keys(), key=len))
    unified_count = 0
    for trace in to_check:
        # check if we can find the next entry if we strip few stack frames
        next_trace = None
        for to_strip in range(1, 4):
            stripped_trace = trace[to_strip:]
            if stripped_trace in traces:
                next_trace = stripped_trace
                break

        if next_trace is None:
            continue

        ratio = traces[trace] / traces[next_trace]
        global_ratio = traces[next_trace] / len(traces)
        if ratio < 0.05 or global_ratio / 0.001:
            unified_count += 1
            traces[next_trace] += traces[trace]
            del traces[trace]

    if options.verbose:
        print("unify step removed {} or {:.1%} traces".format(unified_count, unified_count/pre_count))


def identify_trace(trace):
    for sink in SINKS:
        if any(sink['match'] in frame.name for frame in trace):
            return sink['name']


def filter_newrelic(trace):
    return [frame for frame in trace if 'NewRelic::Agent::Instrumentation::MiddlewareTracing' not in frame.name]


def remove_zeros(traces):
    to_check = list(traces.keys())
    for trace in to_check:
        if traces[trace] == 0:
            del traces[trace]


ST_START = object()
ST_FRAMES = object()
ST_COUNT = object()

Frame = namedtuple('Frame', ('file', 'line', 'name'))

resolution = None


def extract_traces(f):
    global resolution
    data = json.load(f)
    resolution = resolution or data['interval']

    state = ST_START
    for entry in data['raw']:
        if state is ST_START:
            stack = []
            frame_count = entry
            state = ST_FRAMES
        elif state is ST_FRAMES:
            frame = data['frames'][str(entry)]
            stack.append(Frame(file=frame['file'], line=frame.get('line'), name=frame['name']))
            frame_count -= 1
            if frame_count == 0:
                state = ST_COUNT
        elif state is ST_COUNT:
            stack_count = entry
            stack = list(reversed(stack))
            state = ST_START
            yield (stack_count, stack)


def get_traces(options):
    cold_traces = defaultdict(int)
    warm_traces = defaultdict(int)
    stack_dir = options.STACKS_DIR

    cold_stacks_count = 0
    stacks = os.listdir(stack_dir)
    for stack in stacks:
        if '.cold' in stack:
            target = cold_traces
            cold_stacks_count += 1
        elif '.warm' in stack:
            target = warm_traces
        else:
            continue

        with open(os.path.join(stack_dir, stack), 'r') as f:
            if options.verbose:
                print("processing {}".format(stack))
            traces = extract_traces(f)

            for count, trace in traces:
                if options.common_middleware:
                    trace = filter_newrelic(trace)

                # initial line may differ slightly without a change to result
                trace[0] = trace[0]._replace(line=None)

                for i, frame in enumerate(trace):
                    if '_erb_' in frame.name:
                        trace[i] = frame._replace(name=erb_func.sub('_erb', frame.name))
                    if 'Module:' in frame.name:
                        trace[i] = frame._replace(name=module_ptr.sub('Module:ptr', frame.name))
                target[tuple(trace)] += count

    if options.verbose:
        print("warm traces: {}".format(sum(warm_traces.values())))
        print("cold traces: {}".format(sum(cold_traces.values())))

    return warm_traces, cold_traces, cold_stacks_count


def remove_warm(options, warm_traces, cold_traces):
    for trace in warm_traces:
        cold_traces.pop(trace, None)
    if options.verbose:
        print("cold-only traces: {}".format(sum(cold_traces.values())))


def identify_known(cold_traces):
    known_sinks = defaultdict(int)

    for trace in cold_traces:
        known = identify_trace(trace)
        if known:
            known_sinks[known] += cold_traces[trace]
            cold_traces[trace] = 0

    remove_zeros(cold_traces)

    return known_sinks


def identify_templates(traces):
    templates = defaultdict(int)

    prefix = 'ActionView::CompiledTemplates#'
    for trace, count in traces.items():
        for frame in trace:
            if frame.name.startswith(prefix):
                templates[frame.name[len(prefix):]] += count
                traces[trace] = 0
                break

    remove_zeros(traces)
    return templates


def process_known_sinks(options, cold_traces, cold_stacks_count):
    cold_traces_count = sum(cold_traces.values())
    known_sinks = identify_known(cold_traces)
    if options.templates:
        known_templates = identify_templates(cold_traces)
        known_sinks.update(known_templates)

    print("Known time sinks:")
    percentage_total = 0
    skipped = 0
    for sink, count in sorted(known_sinks.items(), key=lambda x: -x[1]):
        percentage = count/cold_traces_count
        percentage_total += percentage
        if percentage >= 0.01:
            duration = count/cold_stacks_count*resolution/1000
            print("{:<55}: {:>6}, {:>6.1%}, {:>6}ms".format(sink, count, percentage, duration))
        else:
            skipped += 1
    print("total time in known: {:.1%} of cold request time".format(percentage_total))
    if skipped > 0:
        print("(skipped {} entries below 1%)".format(skipped))


def report_other_traces(options, cold_traces):
    print()
    print("Top {} traces with no attribution:".format(options.other_length))
    by_popularity = sorted([(count, trace) for trace, count in cold_traces.items() if count > 0], reverse=True)
    for count, trace in by_popularity[:options.other_count]:
        if count == 0:
            break
        print("-----------")
        print("{} occurences".format(count))
        for line in trace[:options.other_length]:
            print("  {}".format(line))
        print()


def main():
    options = parse_args()
    warm_traces, cold_traces, cold_stacks_count = get_traces(options)
    remove_warm(options, warm_traces, cold_traces)

    if options.unify_traces:
        unify_traces(options, cold_traces)

    total_warmup = sum(cold_traces.values())/cold_stacks_count*resolution/1000
    print("Average warmup time per request: {}ms".format(total_warmup))
    print()

    if options.known_sinks and not options.files_only:
        process_known_sinks(options, cold_traces, cold_stacks_count)

    if options.other_length > 0:
        report_other_traces(options, cold_traces)


if __name__ == "__main__":
    main()
