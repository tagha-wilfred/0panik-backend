from django.contrib import admin
from .models import ScamCheck

@admin.register(ScamCheck)
class ScamCheckAdmin(admin.ModelAdmin):
    list_display = ('user', 'verdict', 'source', 'created_at')
    list_filter = ('verdict', 'source')
    search_fields = ('user__email', 'submitted_text')