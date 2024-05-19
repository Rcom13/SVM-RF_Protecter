# -*- coding: utf-8 -*-
from __future__ import division
import numpy as np
import os
from sklearn import svm
from sklearn.ensemble import RandomForestClassifier
import matplotlib.pyplot as plt

def plot_decision_boundary(clf, X, y, ax, title):
    x_min, x_max = X[:, 0].min() - 1, X[:, 0].max() + 1
    y_min, y_max = X[:, 1].min() - 1, X[:, 1].max() + 1
    xx, yy = np.meshgrid(np.arange(x_min, x_max, 0.01),
                         np.arange(y_min, y_max, 0.01))
    Z = clf.predict(np.c_[xx.ravel(), yy.ravel()])
    Z = Z.reshape(xx.shape)
    ax.contourf(xx, yy, Z, alpha=0.8)
    ax.scatter(X[:, 0], X[:, 1], c=y, edgecolors='k', marker='o')
    ax.set_title(title)

def plot_results(results_file, analysis_folder):
    # Load the data
    data = np.loadtxt(open(results_file, 'rb'), delimiter=',')
    # Feature indices
    sfe = 0
    ssip = 1
    rfip = 2

    # Load labels
    y = data[:, 3]

    # Initialize classifiers
    svm_clf = svm.SVC(probability=True)
    rf_clf = RandomForestClassifier(n_estimators=100)

    # Graph1: SVM sfe & ssip
    X = data[:, [sfe, ssip]]
    svm_clf.fit(X, y)
    fig, ax = plt.subplots()
    plot_decision_boundary(svm_clf, X, y, ax, 'SVM - Decision Region Boundary (sfe & ssip)')
    plt.xlabel('Speed of Flow Entry')
    plt.ylabel('Speed of Source IP')
    plt.savefig("{}/svm_sfe_ssip.png".format(analysis_folder))

    # Graph2: RF sfe & ssip
    rf_clf.fit(X, y)
    fig, ax = plt.subplots()
    plot_decision_boundary(rf_clf, X, y, ax, 'RF - Decision Region Boundary (sfe & ssip)')
    plt.xlabel('Speed of Flow Entry')
    plt.ylabel('Speed of Source IP')
    plt.savefig("{}/rf_sfe_ssip.png".format(analysis_folder))

    # Graph3: SVM sfe & rfip
    X = data[:, [sfe, rfip]]
    svm_clf.fit(X, y)
    fig, ax = plt.subplots()
    plot_decision_boundary(svm_clf, X, y, ax, 'SVM - Decision Region Boundary (sfe & rfip)')
    plt.xlabel('Speed of Flow Entry')
    plt.ylabel('Ratio of Flow Pair')
    plt.savefig("{}/svm_sfe_rfip.png".format(analysis_folder))

    # Graph4: RF sfe & rfip
    rf_clf.fit(X, y)
    fig, ax = plt.subplots()
    plot_decision_boundary(rf_clf, X, y, ax, 'RF - Decision Region Boundary (sfe & rfip)')
    plt.xlabel('Speed of Flow Entry')
    plt.ylabel('Ratio of Flow Pair')
    plt.savefig("{}/rf_sfe_rfip.png".format(analysis_folder))
