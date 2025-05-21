from django.contrib import admin
from .models import *
# Register your models here.

admin.site.register(CustomUser)
admin.site.register(ThreatLog)
admin.site.register(ThreatDetection)
admin.site.register(IPReputation)
admin.site.register(IncidentReport)
