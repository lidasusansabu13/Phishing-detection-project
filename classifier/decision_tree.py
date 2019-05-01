from sklearn import svm
from sklearn.metrics import accuracy_score

import numpy as np


def load_data():
    
    training_data = np.genfromtxt('dataset.csv', delimiter=',', dtype=np.int32)

   

    inputs = training_data[:,:-1]

    outputs = training_data[:, -1]

    training_inputs = inputs[:9000]
    training_outputs = outputs[:9000]
    testing_inputs = inputs[9000:]
    testing_outputs = outputs[9000:]

    
    return training_inputs, training_outputs, testing_inputs, testing_outputs


if __name__ == '__main__':
    print "Tutorial: Training a decision tree to detect phishing websites"

    # Load the training data
    train_inputs, train_outputs, test_inputs, test_outputs = load_data()
    print "Training data loaded."

    # Create a decision tree classifier model using scikit-learn
    classifier = svm.SVC(kernel='linear')
    print "Linear SVM  classifier created."

    print "Beginning model training."
    # Train the svm classifier
    classifier.fit(train_inputs, train_outputs)
    print "Model training completed."

    # Use the trained classifier to make predictions on the test data
    predictions = classifier.predict(test_inputs)
    print "Predictions on testing data computed."

    # Print the accuracy (percentage of phishing websites correctly predicted)
    accuracy = 100.0 * accuracy_score(test_outputs, predictions)
    print "The accuracy of your svm on testing data is: " + str(accuracy)
