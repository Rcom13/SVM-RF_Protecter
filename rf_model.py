# rf_model.py
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import pickle

class RFModel:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)

    def train(self, X, y):
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        self.model.fit(X_train, y_train)
        return self.model.score(X_test, y_test)

    def predict(self, X):
        return self.model.predict_proba(X)

    def save_model(self, path='rf_model.pkl'):
        with open(path, 'wb') as f:
            pickle.dump(self.model, f)

    def load_model(self, path='rf_model.pkl'):
        with open(path, 'rb') as f:
            self.model = pickle.load(f)
