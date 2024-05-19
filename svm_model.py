# svm_model.py
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
import pickle

class SVMModel:
    def __init__(self):
        self.model = SVC(kernel='rbf', probability=True)

    def train(self, X, y):
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        self.model.fit(X_train, y_train)
        return self.model.score(X_test, y_test)

    def predict(self, X):
        return self.model.predict_proba(X)

    def save_model(self, path='svm_model.pkl'):
        with open(path, 'wb') as f:
            pickle.dump(self.model, f)

    def load_model(self, path='svm_model.pkl'):
        with open(path, 'rb') as f:
            self.model = pickle.load(f)
