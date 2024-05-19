# -*- coding: utf-8 -*-
from sklearn import svm
import numpy as np
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
import os

def calculate_accuracy(results_file):
    # Step 1: Load the data
    data = np.loadtxt(open(results_file, 'rb'), delimiter=',')
    X = data[:, 0:3]
    y = data[:, 3]

    # Step 2: Split the data into training and test sets
    x_train, x_test, y_train, y_test = train_test_split(X, y, random_state=0, test_size=0.25)

    # Step 3: Initialize and train SVM and RF classifiers
    svm_clf = svm.SVC(kernel="linear", C=0.025)
    rf_clf = RandomForestClassifier(n_estimators=100, random_state=0)
    svm_clf.fit(x_train, y_train)
    rf_clf.fit(x_train, y_train)

    # Step 4: Make predictions
    svm_predictions = svm_clf.predict(x_test)
    rf_predictions = rf_clf.predict(x_test)

    # Step 5: Calculate accuracy
    svm_accuracy = accuracy_score(y_test, svm_predictions)
    rf_accuracy = accuracy_score(y_test, rf_predictions)

    # Step 6: Calculate cross-validation scores
    svm_scores = cross_val_score(svm_clf, x_train, y_train, cv=5)
    rf_scores = cross_val_score(rf_clf, x_train, y_train, cv=5)

    return {
        "svm_accuracy": svm_accuracy,
        "rf_accuracy": rf_accuracy,
        "svm_cv_score": svm_scores.mean(),
        "rf_cv_score": rf_scores.mean()
    }

def write_accuracy_to_file(results_file, analysis_folder):
    accuracy = calculate_accuracy(results_file)
    if not os.path.exists(analysis_folder):
        os.makedirs(analysis_folder)
    with open("{}/accuracy.txt".format(analysis_folder), 'w') as file:
        file.write("SVM Accuracy: {:.2f}%\n".format(svm_accuracy * 100))
        file.write("RF Accuracy: {:.2f}%\n".format(rf_accuracy * 100))
        file.write("SVM cross-validation score: {:.2f}\n".format(svm_scores.mean()))
        file.write("RF cross-validation score: {:.2f}\n".format(rf_scores.mean()))

if __name__ == "__main__":
    results_file = 'result.csv'
    analysis_folder = 'analysis'
    write_accuracy_to_file(results_file, analysis_folder)
