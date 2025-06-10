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
        is_standard_tag = bool(request.form.get('is_standard_tag'))
        rule = Rule(name=name, regex_pattern=regex_pattern, priority=priority, is_standard_tag=is_standard_tag)
        db.session.add(rule)
        db.session.commit()
        flash(f'Rule "{name}" created successfully', 'success')
        return redirect(request.url)
    
    # Get all rules ordered by priority with match counts
    rules = Rule.query.order_by(Rule.priority.asc(), Rule.created_at.asc()).all()
    
    # Calculate match counts for each rule
    rules_with_counts = []
    transactions = Transaction.query.all()
    
    for rule in rules:
        match_count = 0
        for transaction in transactions:
            try:
                if re.search(rule.regex_pattern.lower(), transaction.narration.lower()):
                    match_count += 1
            except re.error:
                continue
        
        rules_with_counts.append({
            'rule': rule,
            'match_count': match_count
        })
    
    return render_template('rules.html', rules_with_counts=rules_with_counts)

@app.route('/rules/edit/<int:rule_id>', methods=['GET', 'POST'])
def edit_rule(rule_id):
    """Edit an existing rule"""
    rule = Rule.query.get_or_404(rule_id)
    
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
        
        # Check if name already exists (excluding current rule)
        existing_rule = Rule.query.filter(Rule.name == name, Rule.id != rule_id).first()
        if existing_rule:
            flash('Rule name already exists', 'error')
            return redirect(request.url)
        
        # Validate regex pattern
        try:
            re.compile(regex_pattern)
        except re.error as e:
            flash(f'Invalid regex pattern: {str(e)}', 'error')
            return redirect(request.url)
        
        # Update rule
        rule.name = name
        rule.regex_pattern = regex_pattern
        rule.priority = priority
        rule.is_standard_tag = bool(request.form.get('is_standard_tag'))
        db.session.commit()
        flash(f'Rule "{name}" updated successfully', 'success')
        return redirect(url_for('manage_rules'))
    
    # GET request - show edit form
    return render_template('edit_rule.html', rule=rule)

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
    
    # Get filter parameters
    show_untagged_only = request.args.get('untagged') == '1'
    rule_filter = request.args.get('rule')
    
    # Start with base query
    query = Transaction.query
    
    # Apply filters
    if show_untagged_only:
        query = query.filter(Transaction.rule_applied.is_(None))
    
    if rule_filter:
        query = query.filter(Transaction.rule_applied == rule_filter)
    
    # Get filtered transactions ordered by serial number
    transactions = query.order_by(Transaction.serial_number.asc()).all()
    
    # Get all unique rule names for filter dropdown
    rule_names = db.session.query(Transaction.rule_applied).filter(
        Transaction.rule_applied.isnot(None)
    ).distinct().all()
    rule_names = [r[0] for r in rule_names if r[0]]
    
    return render_template('transactions.html', 
                         transactions=transactions,
                         rule_names=rule_names,
                         current_rule_filter=rule_filter,
                         show_untagged_only=show_untagged_only)

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

@app.route('/rules/combine', methods=['POST'])
def combine_rules():
    """Combine multiple rules with OR logic"""
    rule_ids_str = request.form.get('rule_ids', '')
    combined_name = request.form.get('combined_name', '').strip()
    combined_priority = request.form.get('combined_priority', 5, type=int)
    delete_originals = request.form.get('delete_originals') == 'on'
    
    # Parse rule IDs
    try:
        rule_ids = [int(id.strip()) for id in rule_ids_str.split(',') if id.strip()]
    except ValueError:
        flash('Invalid rule selection', 'error')
        return redirect(url_for('manage_rules'))
    
    # Validation
    if len(rule_ids) < 2:
        flash('Please select at least 2 rules to combine', 'error')
        return redirect(url_for('manage_rules'))
    
    if not combined_name:
        flash('Combined rule name is required', 'error')
        return redirect(url_for('manage_rules'))
    
    if combined_priority < 1 or combined_priority > 10:
        flash('Priority must be between 1 and 10', 'error')
        return redirect(url_for('manage_rules'))
    
    # Check if name already exists
    if Rule.query.filter_by(name=combined_name).first():
        flash('Combined rule name already exists', 'error')
        return redirect(url_for('manage_rules'))
    
    # Get the rules
    rules = Rule.query.filter(Rule.id.in_(rule_ids)).all()
    if len(rules) != len(rule_ids):
        flash('Some selected rules not found', 'error')
        return redirect(url_for('manage_rules'))
    
    try:
        # Create combined regex pattern with OR logic
        patterns = [f'({rule.regex_pattern})' for rule in rules]
        combined_pattern = '|'.join(patterns)
        
        # Validate the combined pattern
        re.compile(combined_pattern)
        
        # Create new combined rule
        combined_rule = Rule(
            name=combined_name,
            regex_pattern=combined_pattern,
            priority=combined_priority
        )
        db.session.add(combined_rule)
        
        # Delete original rules if requested
        if delete_originals:
            # Update transactions that used the deleted rules
            for rule in rules:
                Transaction.query.filter_by(rule_id=rule.id).update({
                    'rule_applied': None,
                    'rule_id': None
                })
                db.session.delete(rule)
        
        db.session.commit()
        
        message = f'Combined rule "{combined_name}" created successfully'
        if delete_originals:
            message += f' and {len(rules)} original rules deleted'
        flash(message, 'success')
        
    except re.error as e:
        flash(f'Error creating combined pattern: {str(e)}', 'error')
    except Exception as e:
        flash(f'Error combining rules: {str(e)}', 'error')
    
    return redirect(url_for('manage_rules'))

@app.route('/rules/delete-multiple', methods=['POST'])
def delete_multiple_rules():
    """Delete multiple rules at once"""
    rule_ids_str = request.form.get('rule_ids', '')
    
    # Parse rule IDs
    try:
        rule_ids = [int(id.strip()) for id in rule_ids_str.split(',') if id.strip()]
    except ValueError:
        flash('Invalid rule selection', 'error')
        return redirect(url_for('manage_rules'))
    
    if not rule_ids:
        flash('No rules selected for deletion', 'error')
        return redirect(url_for('manage_rules'))
    
    try:
        # Get the rules to delete
        rules = Rule.query.filter(Rule.id.in_(rule_ids)).all()
        
        # Remove rules from transactions that used them
        for rule in rules:
            Transaction.query.filter_by(rule_id=rule.id).update({
                'rule_applied': None,
                'rule_id': None
            })
            db.session.delete(rule)
        
        db.session.commit()
        flash(f'Successfully deleted {len(rules)} rules', 'success')
        
    except Exception as e:
        flash(f'Error deleting rules: {str(e)}', 'error')
    
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

@app.route('/download_rules')
def download_rules():
    """Download all rules as CSV"""
    rules = Rule.query.order_by(Rule.priority.asc(), Rule.created_at.asc()).all()
    
    # Create CSV content
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Rule Name', 'Regex Pattern', 'Priority', 'Standard Tag', 'Created Date'])
    
    # Write rule data
    for rule in rules:
        writer.writerow([
            rule.name,
            rule.regex_pattern,
            rule.priority,
            'Yes' if rule.is_standard_tag else 'No',
            rule.created_at.strftime('%Y-%m-%d %H:%M:%S')
        ])
    
    # Create response
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = 'attachment; filename=rules.csv'
    
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
                if re.search(rule.regex_pattern.lower(), transaction.narration.lower()):
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
    
    # Multiple UPI patterns to cover different formats:
    # Pattern 1: UPI/xxx/UPI/upiid@bank/bank/xxx (traditional format)
    # Pattern 2: UPI/upiid/NA/bank/xxx/xxx (paytm QR format)  
    # Pattern 3: UPI/upiid/xxx/bank/xxx/xxx (apple services format)
    # Pattern 4: UPI/xxx/UPI/phonenumber@bank/bank/xxx (mobile number format)
    upi_patterns = [
        r'UPI/[^/]*/UPI/([^@/]+@[^/]+)/',  # Traditional: swiggystores@ic, 9999999999@xyz
        r'UPI/([^/]+)/NA/',                # PayTM QR: paytmqr28100505
        r'UPI/([^/]+\.b)/',               # Apple services: appleservices.b
        r'UPI/([^/]+)/MandateRequest/'    # Apple mandate: appleservices.b
    ]
    
    existing_upi_rules = set()
    # Get existing UPI rules to avoid duplicates (check for @ symbol or common UPI patterns)
    existing_rules = Rule.query.filter(
        db.or_(
            Rule.name.like('%@%'),
            Rule.name.like('paytmqr%'),
            Rule.name.like('%.b'),
            Rule.name.like('%services%')
        )
    ).all()
    for rule in existing_rules:
        existing_upi_rules.add(rule.name.lower())
    
    new_upi_ids = set()
    
    # Scan all transactions for UPI IDs using all patterns
    # Store UPI ID with the pattern that found it
    upi_id_patterns = {}
    for transaction in transactions:
        for i, pattern in enumerate(upi_patterns):
            matches = re.findall(pattern, transaction.narration, re.IGNORECASE)
            for upi_id in matches:
                upi_id_clean = upi_id.strip().lower()
                if upi_id_clean and upi_id_clean not in existing_upi_rules and len(upi_id_clean) > 2:
                    new_upi_ids.add(upi_id_clean)
                    upi_id_patterns[upi_id_clean] = i  # Store which pattern found this UPI ID
    
    # Create rules for new UPI IDs
    for upi_id in new_upi_ids:
        try:
            # Create a regex pattern that matches this specific UPI ID
            escaped_upi = re.escape(upi_id)
            
            # Generate pattern based on which extraction pattern found this UPI ID
            pattern_index = upi_id_patterns.get(upi_id, 0)
            
            if pattern_index == 0:
                # Traditional format: UPI/xxx/UPI/upiid@bank/
                regex_pattern = f'UPI/[^/]*/UPI/{escaped_upi}/'
            elif pattern_index == 1:
                # PayTM format: UPI/upiid/NA/
                regex_pattern = f'UPI/{escaped_upi}/NA/'
            elif pattern_index == 2:
                # Apple services format: UPI/upiid.b/
                regex_pattern = f'UPI/{escaped_upi}/'
            elif pattern_index == 3:
                # Apple mandate format: UPI/upiid/MandateRequest/
                regex_pattern = f'UPI/{escaped_upi}/MandateRequest/'
            else:
                # Fallback: generic format
                regex_pattern = f'UPI/{escaped_upi}/'
            
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
