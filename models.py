from app import db
from datetime import datetime

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.Integer, nullable=False)
    narration = db.Column(db.Text, nullable=False)
    rule_applied = db.Column(db.String(100), nullable=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    rule = db.relationship('Rule', backref='transactions')
    
    def __repr__(self):
        return f'<Transaction {self.serial_number}: {self.narration[:50]}>'

class Rule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    regex_pattern = db.Column(db.Text, nullable=False)
    priority = db.Column(db.Integer, nullable=False, default=5)
    is_standard_tag = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Rule {self.name}: Priority {self.priority}>'
