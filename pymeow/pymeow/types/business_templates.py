"""
Business message template types for PyMeow.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Union, Literal

from .jid import JID

class TemplateComponentType(str, Enum):
    """Types of components in a message template."""
    HEADER = "HEADER"
    BODY = "BODY"
    FOOTER = "FOOTER"
    BUTTONS = "BUTTONS"

class TemplateButtonType(str, Enum):
    """Types of buttons in a message template."""
    QUICK_REPLY = "QUICK_REPLY"
    URL = "URL"
    PHONE_NUMBER = "PHONE_NUMBER"

class TemplateFormat(str, Enum):
    """Format of the template."""
    TEXT = "TEXT"
    IMAGE = "IMAGE"
    DOCUMENT = "DOCUMENT"
    VIDEO = "VIDEO"

class TemplateCategory(str, Enum):
    """Category of the template."""
    MARKETING = "MARKETING"
    UTILITY = "UTILITY"
    AUTHENTICATION = "AUTHENTICATION"

class TemplateStatus(str, Enum):
    """Status of the template."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    PAUSED = "PAUSED"

class TemplateLanguage(str, Enum):
    """Supported languages for templates."""
    AF = "af"
    SQ = "sq"
    AR = "ar"
    AZ = "az"
    BN = "bn"
    BG = "bg"
    CA = "ca"
    ZH_CN = "zh_CN"
    ZH_HK = "zh_HK"
    ZH_TW = "zh_TW"
    HR = "hr"
    CS = "cs"
    DA = "da"
    NL = "nl"
    EN = "en"
    EN_GB = "en_GB"
    EN_US = "en_US"
    ET = "et"
    FIL = "fil"
    FI = "fi"
    FR = "fr"
    DE = "de"
    EL = "el"
    GU = "gu"
    HA = "ha"
    HE = "he"
    HI = "hi"
    HU = "hu"
    ID = "id"
    GA = "ga"
    IT = "it"
    JA = "ja"
    KN = "kn"
    KK = "kk"
    KO = "ko"
    LO = "lo"
    LV = "lv"
    LT = "lt"
    MK = "mk"
    MS = "ms"
    ML = "ml"
    MR = "mr"
    NB = "nb"
    FA = "fa"
    PL = "pl"
    PT_BR = "pt_BR"
    PT_PT = "pt_PT"
    PA = "pa"
    RO = "ro"
    RU = "ru"
    SR = "sr"
    SK = "sk"
    SL = "sl"
    ES = "es"
    ES_AR = "es_AR"
    ES_ES = "es_ES"
    ES_MX = "es_MX"
    SW = "sw"
    SV = "sv"
    TA = "ta"
    TE = "te"
    TH = "th"
    TR = "tr"
    UK = "uk"
    UR = "ur"
    UZ = "uz"
    VI = "vi"

@dataclass
class TemplateButton:
    """A button in a message template."""
    type: TemplateButtonType
    text: str
    url: Optional[str] = None
    phone_number: Optional[str] = None
    example: Optional[Union[str, List[str]]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary."""
        data = {
            'type': self.type.value,
            'text': self.text,
        }
        
        if self.url:
            data['url'] = self.url
        if self.phone_number:
            data['phone_number'] = self.phone_number
        if self.example is not None:
            data['example'] = self.example
            
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TemplateButton':
        """Create from a dictionary."""
        return cls(
            type=TemplateButtonType(data['type']),
            text=data['text'],
            url=data.get('url'),
            phone_number=data.get('phone_number'),
            example=data.get('example'),
        )

@dataclass
class TemplateComponent:
    """A component in a message template."""
    type: TemplateComponentType
    text: Optional[str] = None
    buttons: List[TemplateButton] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary."""
        data = {'type': self.type.value}
        
        if self.text is not None:
            data['text'] = self.text
        if self.buttons:
            data['buttons'] = [btn.to_dict() for btn in self.buttons]
            
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TemplateComponent':
        """Create from a dictionary."""
        return cls(
            type=TemplateComponentType(data['type']),
            text=data.get('text'),
            buttons=[TemplateButton.from_dict(btn) for btn in data.get('buttons', [])],
        )

@dataclass
class MessageTemplate:
    """A WhatsApp Business message template."""
    name: str
    language: TemplateLanguage
    category: TemplateCategory
    components: List[TemplateComponent] = field(default_factory=list)
    status: TemplateStatus = TemplateStatus.PENDING
    namespace: Optional[str] = None
    rejected_reason: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    @property
    def is_approved(self) -> bool:
        """Check if the template is approved."""
        return self.status == TemplateStatus.APPROVED
    
    @property
    def is_rejected(self) -> bool:
        """Check if the template is rejected."""
        return self.status == TemplateStatus.REJECTED
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for API requests."""
        data = {
            'name': self.name,
            'language': self.language.value,
            'category': self.category.value,
            'components': [comp.to_dict() for comp in self.components],
        }
        
        if self.namespace:
            data['namespace'] = self.namespace
            
        return data
    
    def to_export_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for exporting/importing."""
        data = self.to_dict()
        data.update({
            'status': self.status.value,
            'rejected_reason': self.rejected_reason,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        })
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MessageTemplate':
        """Create from a dictionary."""
        created_at = (
            datetime.fromisoformat(data['created_at'])
            if 'created_at' in data and data['created_at']
            else None
        )
        
        updated_at = (
            datetime.fromisoformat(data['updated_at'])
            if 'updated_at' in data and data['updated_at']
            else None
        )
        
        return cls(
            name=data['name'],
            language=TemplateLanguage(data.get('language', 'en')),
            category=TemplateCategory(data['category']),
            components=[
                TemplateComponent.from_dict(comp)
                for comp in data.get('components', [])
            ],
            status=TemplateStatus(data.get('status', 'PENDING')),
            namespace=data.get('namespace'),
            rejected_reason=data.get('rejected_reason'),
            created_at=created_at,
            updated_at=updated_at,
        )

@dataclass
class TemplateMessage:
    """A message that uses a template."""
    name: str
    language: str
    namespace: Optional[str] = None
    components: Optional[List[Dict[str, Any]]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for API requests."""
        data = {
            'name': self.name,
            'language': {'code': self.language},
        }
        
        if self.namespace:
            data['namespace'] = self.namespace
        if self.components:
            data['components'] = self.components
            
        return {'type': 'template', 'template': data}
