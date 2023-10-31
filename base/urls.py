from django.urls import path
from . import views
# from .views import DataCollectionView, malware_prediction
from .views import  malware_prediction

urlpatterns = [
    path("malpredict",views.malware_prediction),
    path("datacollection",views.dataCollection),
    # path('datacollection', DataCollectionView.as_view(), name='data_collection'),
    # path("maltest",views.mTest1),
    # path("maltest2",views.mTest2),
]

