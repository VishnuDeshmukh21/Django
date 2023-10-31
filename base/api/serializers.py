from rest_framework import serializers
from django.contrib.auth.models import User

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)  # Include password field for writing only

    class Meta:
        model = User
        fields = ('id', 'username', 'password')

    def create(self, validated_data):
        user = User(username=validated_data['username'])
        user.set_password(validated_data['password'])  # Hash the password before saving
        user.save()
        return user
