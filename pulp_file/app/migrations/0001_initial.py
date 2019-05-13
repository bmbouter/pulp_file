# Generated by Django 2.2.1 on 2019-05-09 16:50

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('core', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='FilePublication',
            fields=[
                ('publication_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='core.Publication')),
            ],
            options={
                'abstract': False,
            },
            bases=('core.publication',),
        ),
        migrations.CreateModel(
            name='FilePublisher',
            fields=[
                ('publisher_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='core.Publisher')),
                ('manifest', models.TextField()),
            ],
            options={
                'abstract': False,
            },
            bases=('core.publisher',),
        ),
        migrations.CreateModel(
            name='FileRemote',
            fields=[
                ('remote_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='core.Remote')),
            ],
            options={
                'abstract': False,
            },
            bases=('core.remote',),
        ),
        migrations.CreateModel(
            name='FileDistribution',
            fields=[
                ('basedistribution_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, related_name='_distributions', serialize=False, to='core.BaseDistribution')),
                ('publication', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='_distributions', to='core.Publication')),
            ],
            options={
                'abstract': False,
                'default_related_name': '_distributions',
            },
            bases=('core.basedistribution',),
        ),
        migrations.CreateModel(
            name='FileContent',
            fields=[
                ('content_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='core.Content')),
                ('relative_path', models.CharField(max_length=255)),
                ('digest', models.CharField(max_length=64)),
            ],
            options={
                'unique_together': {('relative_path', 'digest')},
            },
            bases=('core.content',),
        ),
    ]