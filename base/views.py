import pandas as pd
import numpy as np
import csv
import os
import re
import pickle 
import json

from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse, JsonResponse
from django.utils.decorators import method_decorator
from django.views import View

from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.linear_model import SGDClassifier
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.preprocessing import MinMaxScaler
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS
from sklearn.preprocessing import MinMaxScaler
from sklearn.feature_extraction.text import TfidfVectorizer

from pymongo import MongoClient

from asgiref.sync import sync_to_async


models = []

class MalwareDetection:
    def __init__(self):
        """ Load pre-trained random forest classifier during object initialization """
        self.clf=pickle.load(open("static/rf.pkl", "rb"))

    def predict(self,normalized_features):
            """
            Predicts whether input data is Malware or Goodware.

            Args:
                normalized_features (list): List of normalized features extracted from input data.

            Returns:
                dict: Dictionary with keys "Label" and "Confidence level".
            """
            y_pred = self.clf.predict(np.asarray(normalized_features))
            pred_proba = self.clf.predict_proba(np.asarray(normalized_features))
    
            pred_proba_percent1 = np.around(pred_proba[0] * 100, decimals=2)
            i = 0
            for label, conf in zip(y_pred, pred_proba_percent1):
                if label == 0:
                    d1={ "Label":"Goodware", "Confidence level" : int(conf)}
                else:
                    d1={ "Label":"Malware", "Confidence level" : int(conf)}
                i += 1
            return d1

    def extract_features(self,data):
            """
            Extracts and transforms static features from input data.

            Args:
                data (dict): Dictionary containing static features extracted from input data.

            Returns:
                np.ndarray: Numpy array containing transformed features.
            """
            static_features = {
                    'api_call': data.get('APICall'),
                    'permission': data.get('Permission'),
                    'url': data.get('URL'),
                    'provider': data.get('Provider'),
                    'feature': data.get('Feature'),
                    'intent': data.get('Intent'),
                    'activity': data.get('Activity'),
                    'call': data.get('Call'),
                    'service_receiver': data.get('ServiceReceiver'),
                    'real_permission': data.get('RealPermission')
                }
            ext_data=pd.DataFrame(static_features,index=[0])
            extracted_data=[]
            for i in range(ext_data.shape[1]):
                test_data = ext_data.values[:,i]
                tfidf = pickle.load(open("static/tfidf_col{}.pkl".format(i), "rb"))
                test_tfidf = tfidf.transform(test_data).todense()
                if len(extracted_data) == 0:
                    extracted_data = test_tfidf
                else:
                    extracted_data = np.concatenate((extracted_data, test_tfidf), axis=1)
            return(extracted_data)


@csrf_exempt
@sync_to_async
def malware_prediction(request):
    """
    View function for malware prediction API.

    This function handles POST requests containing JSON data for malware prediction.
    It extracts features from the input data, predicts the malware using the MalwareDetection class,
    and returns the prediction result as a JSON response.

    Args:
        request (HttpRequest): The HTTP request object containing POST data.

    Returns:
        JsonResponse: JSON response containing the malware prediction result.
    """
    try:
        result = {}
        if request.method == 'POST':
            # Extracts the 'stringToAppend' data from the POST request
            string_to_append = request.POST.get('stringToAppend')
            print("In")
            try:
                # Parses the JSON data received from the request
                data = json.loads(string_to_append)
                print(data)
            except json.JSONDecodeError as e:
                # Handles the case where the JSON data is invalid and returns a 400 Bad Request response
                return HttpResponse("Invalid JSON data", status=400)
            
            # Instantiates the MalwareDetection class for prediction
            predictor = MalwareDetection()
            
            # Extracts features from the input data
            X1_test = predictor.extract_features(data)
            
            # Predicts malware using the extracted features
            result = predictor.predict(X1_test)
            print(JsonResponse(result, safe=False))
            
            # Returns the prediction result as a JSON response
            return JsonResponse(result, safe=False)
    except Exception as e:
        # Handles internal server errors and returns a meaningful error response
        return HttpResponseServerError("Internal Server Error", status=500)
    else:
        # Handles the error case where a GET request is made to a POST-only view
        return HttpResponseBadRequest("Invalid request method. POST method required. Bad Request (400)")





@csrf_exempt
@sync_to_async
def dataCollection(request):
    """
    Handles a POST request for collecting data and storing it in a MongoDB database.

    This view function expects a POST request containing a JSON object with data to be collected.
    The JSON data is parsed and stored in a MongoDB database named 'testdb' in the 'static' collection.

    Args:
        request (HttpRequest): The HTTP request object containing JSON data.

    Returns:
        JsonResponse: JSON response indicating the success of the data collection process.
                      If there is an error in the input data format, returns a 400 Bad Request response.
    """
    if request.method == 'POST':
        string_to_append = request.POST.get('stringToAppend')        
        try:
            data = json.loads(string_to_append)
        except json.JSONDecodeError as e:
            return HttpResponse("Invalid JSON data", status=400)
        try:
            # Establish a connection to the MongoDB server running on localhost at port 27017
            client = MongoClient('mongodb://localhost:27017/')
            # Access the 'testdb' database
            db = client['testdb']
            # Access the 'static' collection within the 'testdb' database
            collection = db['static']
            # Insert the JSON data into the 'static' collection
            collection.insert_one(data)
            # Close the MongoDB client connection
            client.close()
            print({"Success": 1})
            return JsonResponse({"Success": 1})
        except Exception as e:
                # Handle database connection or insertion errors
                return HttpResponseServerError("Internal Server Error", status=500)


""" Error Handling """
from django.http import HttpResponseBadRequest, HttpResponseForbidden, HttpResponseNotFound, HttpResponseServerError

def badRequest(request,exception):
    return HttpResponseBadRequest(f"The request could not be understood. Check the request syntax. Error:{exception})")

def serverError(request):
    return HttpResponseServerError("An unexpected error occurred on the server.Internal Server Error (500)")

def forbiddenError(request, exception):
    return HttpResponseForbidden("Access to the requested resource is forbidden.Forbidden (403)")

def pageNotFoundError(request, exception):
    return HttpResponseNotFound("The requested page could not be found.Page Not Found (404)")