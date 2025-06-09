import re
import csv
import io
import pandas as pd
from flask import render_template, request, redirect, url_for, flash, make_response
from app import app, db
from models import Transaction, Rule

@app.route('/')
def index():
    """Home page with navigation to main functions"""
    transaction_count = Transaction.query.count()
    rule_count = Rule.query.count()
    return render_template('index.html', 
                         transaction_count=transaction_count, 
                         rule_count=rule_count)

@app.route('/upload', methods=['GET', 'POST'])
def upload_csv():
    """Function 1: Upload CSV bank statement"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        if not file.filename or not file.filename.lower().endswith('.csv'):
            flash('Please upload a CSV file', 'error')
            return redirect(request.url)
        
        try:
            # Read CSV content
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            csv_input = csv.reader(stream)
            
            # Clear existing transactions
            Transaction.query.delete()
            db.session.commit()
            
            # Process CSV rows
            transactions_added = 0
            for row_num, row in enumerate(csv_input, 1):
                if row and len(row) > 0:  # Skip empty rows
                    narration = row[0].strip()  # Take first column as narration
                    if narration:  # Skip empty narrations
                        transaction = Transaction(
                            serial_number=row_num,
                            narration=narration
                        )
                        db.session.add(transaction)
                        transactions_added += 1
            
            db.session.commit()
            flash(f'Successfully uploaded {transactions_added} transactions', 'success')
            return redirect(url_for('view_transactions'))
            
        except Exception as e:
            flash(f'Error processing CSV: {str(e)}', 'error')
            return redirect(request.url)
    
    return render_template('upload.html')

@app.route('/rules', methods=['GET', 'POST'])
def manage_rules():
    """Function 2: Create and manage regex rules"""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        regex_pattern = request.form.get('regex_pattern', '').strip()
        priority = request.form.get('priority', 5, type=int)
        
        # Validation
        if not name:
            flash('Rule name is required', 'error')
            return redirect(request.url)
        
        if not regex_pattern:
            flash('Regex pattern is required', 'error')
            return redirect(request.url)
        
        if priority < 1 or priority > 10:
            flash('Priority must be between 1 and 10', 'error')
            return redirect(request.url)
        
        # Check if name already exists
        if Rule.query.filter_by(name=name).first():
            flash('Rule name already exists', 'error')
            return redirect(request.url)
        
        # Validate regex pattern
        try:
            re.compile(regex_pattern)
        except re.error as e:
            flash(f'Invalid regex pattern: {str(e)}', 'error')
            return redirect(request.url)
        
        # Create new rule
        rule = Rule(name=name, regex_pattern=regex_pattern, priority=priority)
        db.session.add(rule)
        db.session.commit()
        flash(f'Rule "{name}" created successfully', 'success')
        return redirect(request.url)
    
    # Get all rules ordered by priority
    rules = Rule.query.order_by(Rule.priority.asc(), Rule.created_at.asc()).all()
    return render_template('rules.html', rules=rules)

@app.route('/rules/delete/<int:rule_id>', methods=['POST'])
def delete_rule(rule_id):
    """Delete a rule"""
    rule = Rule.query.get_or_404(rule_id)
    
    # Remove rule from transactions that used it
    Transaction.query.filter_by(rule_id=rule_id).update({
        'rule_applied': None,
        'rule_id': None
    })
    
    db.session.delete(rule)
    db.session.commit()
    flash(f'Rule "{rule.name}" deleted successfully', 'success')
    return redirect(url_for('manage_rules'))

@app.route('/transactions')
def view_transactions():
    """Function 3: View transactions with applied rules"""
    # Apply rules to transactions (includes auto-creating UPI rules)
    apply_rules_to_transactions()
    
    # Get all transactions ordered by serial number
    transactions = Transaction.query.order_by(Transaction.serial_number.asc()).all()
    return render_template('transactions.html', transactions=transactions)

@app.route('/auto-create-upi-rules', methods=['POST'])
def manual_create_upi_rules():
    """Manually trigger UPI rule creation"""
    try:
        before_count = Rule.query.count()
        auto_create_upi_rules()
        after_count = Rule.query.count()
        new_rules = after_count - before_count
        
        if new_rules > 0:
            flash(f'Created {new_rules} new UPI rules automatically', 'success')
        else:
            flash('No new UPI IDs found to create rules for', 'info')
    except Exception as e:
        flash(f'Error creating UPI rules: {str(e)}', 'error')
    
    return redirect(url_for('manage_rules'))

@app.route('/transactions/download')
def download_transactions():
    """Download transactions as CSV"""
    transactions = Transaction.query.order_by(Transaction.serial_number.asc()).all()
    
    # Create CSV content
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Serial Number', 'Narration', 'Rule Applied'])
    
    for transaction in transactions:
        writer.writerow([
            transaction.serial_number,
            transaction.narration,
            transaction.rule_applied or ''
        ])
    
    # Create response
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = 'attachment; filename=transactions_with_rules.csv'
    return response

def apply_rules_to_transactions():
    """Apply regex rules to transactions based on priority"""
    # First, auto-create UPI rules
    auto_create_upi_rules()
    
    # Get all rules ordered by priority (1 is highest priority)
    rules = Rule.query.order_by(Rule.priority.asc(), Rule.created_at.asc()).all()
    
    # Get all transactions
    transactions = Transaction.query.all()
    
    for transaction in transactions:
        # Reset rule application
        transaction.rule_applied = None
        transaction.rule_id = None
        
        # Apply first matching rule (highest priority wins)
        for rule in rules:
            try:
                if re.search(rule.regex_pattern, transaction.narration, re.IGNORECASE):
                    transaction.rule_applied = rule.name
                    transaction.rule_id = rule.id
                    break  # Stop at first match due to priority
            except re.error:
                # Skip invalid regex patterns
                continue
    
    db.session.commit()

def auto_create_upi_rules():
    """Automatically create rules for UPI IDs found in transactions"""
    # Get all transactions
    transactions = Transaction.query.all()
    
    # UPI pattern: looks for UPI IDs in format "xxxxx@yyyy"
    upi_pattern = r'UPI/[^/]*/[^/]*/([^@/]+@[^/]+)/'
    
    existing_upi_rules = set()
    # Get existing UPI rules to avoid duplicates
    existing_rules = Rule.query.filter(Rule.name.like('%@%')).all()
    for rule in existing_rules:
        existing_upi_rules.add(rule.name.lower())
    
    new_upi_ids = set()
    
    # Scan all transactions for UPI IDs
    for transaction in transactions:
        matches = re.findall(upi_pattern, transaction.narration, re.IGNORECASE)
        for upi_id in matches:
            upi_id_clean = upi_id.strip().lower()
            if upi_id_clean and upi_id_clean not in existing_upi_rules:
                new_upi_ids.add(upi_id_clean)
    
    # Create rules for new UPI IDs
    for upi_id in new_upi_ids:
        try:
            # Create a regex pattern that matches this specific UPI ID
            escaped_upi = re.escape(upi_id)
            regex_pattern = f'UPI/[^/]*/[^/]*/{escaped_upi}/'
            
            # Create the rule
            rule = Rule(
                name=upi_id,
                regex_pattern=regex_pattern,
                priority=5
            )
            db.session.add(rule)
            existing_upi_rules.add(upi_id)
            
        except Exception as e:
            # Skip if there's any error creating the rule
            continue
    
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
