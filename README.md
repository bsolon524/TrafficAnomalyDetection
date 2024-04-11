# TrafficAnomalyDetection
This repository is for anomaly detection in network traffic.  It uses a pretrained model to detect anomalies within the traffic we create.  the model is sklearn using IsolationForest.  We used the same model and retrianed it on datasets from Network anomaly detection or it can be found here: https://www.kaggle.com/datasets/anushonkar/network-anamoly-detection/data

There is a folder called  "archive" which has the datasets: train and test.  We use these files to train and test the model we used for overall project.  Next, we create our own network traffic to be sent to local host.  It can be sent to one device to another, we just decided to use local host for simplicity.  We use sockets within the server and client python files to send and recieve packets.  

We then use Wireshark or in this case pyshark, which is a python wrapper for wireshark.  We can use methods to capture the traffic over the local host.  It then uses the model we trained to predict what anamolies are within the traffic we sent.  It then dsiplays its metrics, showing how accurate the model was in detecting the anamolies.

This project has been authored by Seth Canada.