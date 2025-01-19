from django.db import models

# Create your models here.


class Dataset(models.Model):
    title = models.CharField(max_length=200)
    file = models.FileField(upload_to='datasets/')
    uploaded_at = models.DateTimeField(auto_now_add=True) 
  
    class Meta:
        db_table = 'dataset_table'
