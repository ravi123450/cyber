# Generated by Django 4.2.4 on 2023-09-01 06:43

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('user_id', models.AutoField(primary_key=True, serialize=False)),
                ('user_name', models.CharField(max_length=50)),
                ('user_email', models.EmailField(max_length=50)),
                ('user_password', models.CharField(max_length=50)),
                ('user_phone', models.CharField(max_length=50)),
                ('user_location', models.CharField(default='Unknown', max_length=50)),
                ('user_profile', models.ImageField(upload_to='images/user')),
                ('status', models.CharField(default='Pending', max_length=15)),
                ('otp', models.CharField(default=0, max_length=6)),
            ],
            options={
                'db_table': 'User_details',
            },
        ),
    ]
