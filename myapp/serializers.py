from rest_framework import serializers
from myapp.models import User

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["email", "name", "password", "confirm_password"]

    def validate(self, attrs):
        password = attrs.get('password')
        print("password ",password)
        confirm_password = attrs.get('confirm_password')
        print("confirm password ",confirm_password)

        if password != confirm_password:
            raise serializers.ValidationError("Password not match")
        return attrs

    def validate_email(self, value):
        print("value ",value)
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("User with email already exists")
        return value

    def create(self, validated_data):
        user = User.objects.create_user(
            name=validated_data['name'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        user.is_active = False
        user.save()
        return user

    def update(self, instance, validated_data):
        instance.name=validated_data.get('name', instance.name)
        instance.save()
        return instance