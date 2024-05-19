# -*- coding: utf-8 -*-
from sklearn import svm
from sklearn.ensemble import RandomForestClassifier
import numpy as np
from sklearn.model_selection import train_test_split
import os

def calculate_metrics(predictions, y_test):
    DD = DN = FD = TN = 0
    for i in range(len(y_test)):
        if y_test[i] == 1.0:
            if predictions[i] == 1.0:
                DD += 1
            else:
                DN += 1
        elif y_test[i] == 0.0:
            if predictions[i] == 1.0:
                FD += 1
            else:
                TN += 1
    DR = DD / (DD + DN) if (DD + DN) > 0 else 0
    FAR = FD / (FD + TN) if (FD + TN) > 0 else 0
    return DR, FAR

def calculate_detection_rate(results_file):
    # Step 1: Load the data
    data = np.loadtxt(open(results_file, 'rb'), delimiter=',')
    
    # Step 2: Split the data into training and test sets
    X = data[:, 0:3]  # Assuming the first three columns are features
    y = data[:, 3]    # Assuming the fourth column is the label
    x_train, x_test, y_train, y_test = train_test_split(X, y, random_state=0, test_size=0.25)
    
    # Step 3: Initialize SVM and RF classifiers
    svm_clf = svm.SVC()
    rf_clf = RandomForestClassifier(n_estimators=100)  # Adjust n_estimators if necessary
    
    # Step 4: Train the classifiers
    svm_clf.fit(x_train, y_train)
    rf_clf.fit(x_train, y_train)
    
    # Step 5: Make predictions
    svm_predictions = svm_clf.predict(x_test)
    rf_predictions = rf_clf.predict(x_test)
    
    # Step 6: Calculate the Detection Ratio and False Alarm Rate for both classifiers
    svm_DR, svm_FAR = calculate_metrics(svm_predictions, y_test)
    rf_DR, rf_FAR = calculate_metrics(rf_predictions, y_test)
    
    return {
        "svm_DR": svm_DR,
        "svm_FAR": svm_FAR,
        "rf_DR": rf_DR,
        "rf_FAR": rf_FAR
    }

def write_detection_rate_to_file(results_file, analysis_folder):
    detection_rate = calculate_detection_rate(results_file)
    if not os.path.exists(analysis_folder):
        os.makedirs(analysis_folder)
    with open("{}/detection_rate.txt".format(analysis_folder), 'w') as file:
        file.write("SVM Detection Rate: {:.2f}\n".format(svm_DR))
        file.write("SVM False Alarm Rate: {:.2f}\n".format(svm_FAR))
        file.write("RF Detection Rate: {:.2f}\n".format(rf_DR))
        file.write("RF False Alarm Rate: {:.2f}\n".format(rf_FAR))

if __name__ == "__main__":
    results_file = 'result.csv'
    analysis_folder = 'analysis'
    write_detection_rate_to_file(results_file, analysis_folder)
