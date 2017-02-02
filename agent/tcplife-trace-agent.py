#!/usr/bin/python

from bcc import BPF
import ctypes as ct
from json import JSONDecoder, JSONEncoder
import pika
from socket import inet_ntop, ntohs, AF_INET
from struct import pack
from subprocess import Popen, PIPE
from sys import argv
from time import time

# event data
TASK_COMM_LEN = 16

class Data_ipv4(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("saddr", ct.c_ulonglong),
        ("daddr", ct.c_ulonglong),
        ("ports", ct.c_ulonglong),
        ("rx_b", ct.c_ulonglong),
        ("tx_b", ct.c_ulonglong),
        ("span_us", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN)
    ]

NODE = "amqp://monitor:monitor@192.168.222.59:5672/monitor"

start_ts = 0
events = []

def main():
    parameters = pika.URLParameters(NODE)
    connection = pika.BlockingConnection(parameters)

    channel = connection.channel()

    channel.exchange_declare(exchange='monitor',
                             type='topic')

    result = channel.queue_declare(exclusive=True)
    queue_name = result.method.queue

    channel.queue_bind(exchange='monitor',
                       queue=queue_name,
                       routing_key='etcd1.sense.tcplife')


    #def callback(ch, method, properties, body):
    #    print(" [x] %r:%r" % (method.routing_key, body))

    channel.basic_consume(callback,
                          queue=queue_name,
                          no_ack=True)

    channel.start_consuming()


def callback(ch, method, properties, body):
    #config = argv[1] if len(argv) > 1 else '{"duration":10}'
    params = JSONDecoder().decode(body) 
    duration = params["duration"]

    # initialize BPF
    b = BPF(text = bpf_text())
    # read events
    b["ipv4_events"].open_perf_buffer(capture_ipv4_event)

    start_time = time()
    while ((time() - start_time) < duration):
        b.kprobe_poll(timeout=100)

    doc = JSONEncoder().encode(events)
    send_msg(doc)


def send_msg(msg):
    parameters = pika.URLParameters(NODE)
    connection = pika.BlockingConnection(parameters)

    channel = connection.channel()

    channel.exchange_declare(exchange='monitor',
                             type='topic')


    channel.basic_publish(exchange='monitor',
                          routing_key='controller.trace.tcplife',
                          body=msg)

    connection.close()


# process event
def capture_ipv4_event(cpu, data, size):
    global start_ts
    global list_events

    event = ct.cast(data, ct.POINTER(Data_ipv4)).contents

    if start_ts == 0:
        start_ts = event.ts_us

    d = {}
    d["time"] = (float(event.ts_us) - start_ts) / 1000000
    d["pid"] = event.pid
    d["comm"] = event.task
    d["saddr"] = inet_ntop(AF_INET, pack("I", event.saddr))
    d["sport"] = event.ports >> 32
    d["daddr"] = inet_ntop(AF_INET, pack("I", event.daddr))
    d["dport"] = event.ports & 0xffffffff
    d["span"] = float(event.span_us) / 1000
    events.append(d)


def bpf_text():
    with open('tcplife.c', 'r') as f:
        code = f.read()

    # code substitutions
    p = Popen(["pgrep", "etcd"], stdout=PIPE)
    out, err = p.communicate()
    if out:
        pids = out.splitlines()
        snippit = 'if (pid != %d) { return 0; }' % int(pids[0])
        code = code.replace('FILTER_PID', snippit)
    else:
        code = code.replace('FILTER_PID', '')

    return code 


if __name__ == '__main__':
    main()
