# Generated by Django 3.2.5 on 2024-06-27 18:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0007_reservation'),
    ]

    operations = [
        migrations.AddField(
            model_name='reservation',
            name='expires_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]