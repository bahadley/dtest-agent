#!/usr/bin/env python

import pika
import subprocess
import sys

broker_url = 'amqp://monitor:monitor@192.168.222.59:5672/monitor'
exchange_name = 'monitor'
binding_key = 'etcd0.execute.kill'

parameters = pika.URLParameters(broker_url)
connection = pika.BlockingConnection(parameters)

channel = connection.channel()

channel.exchange_declare(exchange=exchange_name,
                         type='topic')

result = channel.queue_declare(exclusive=True)
queue_name = result.method.queue

channel.queue_bind(exchange=exchange_name,
                   queue=queue_name,
                   routing_key=binding_key)

def callback(ch, method, properties, body):
    subprocess.call(["pkill", body, "-u", "root", "etcd"])

channel.basic_consume(callback,
                      queue=queue_name,
                      no_ack=True)

channel.start_consuming()
